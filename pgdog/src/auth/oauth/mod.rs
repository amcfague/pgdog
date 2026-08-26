//! OAuth client authentication.

mod introspection;
mod jwt;
pub mod protocol;

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use oauth2::ClientSecret;
use once_cell::sync::Lazy;
use parking_lot::Mutex as ParkingMutex;
use pgdog_config::{OAuth, OAuthMode};
use reqwest::{Client, RequestBuilder, Response, Url, redirect};
use serde::Deserialize;
use serde::de::{DeserializeOwned, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::Instant;

const MAX_PROVIDER_BODY_LEN: usize = 1024 * 1024;
const MAX_JWKS_KEYS: usize = 128;
const UNKNOWN_KID_REFRESH_COOLDOWN: Duration = Duration::from_secs(5);

static ADMISSION: Lazy<Arc<OAuthAdmission>> = Lazy::new(|| Arc::new(OAuthAdmission::new(64)));

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    #[error("OAuth validation is at capacity")]
    Overloaded,
    #[error("OAuth validation is at capacity for this network peer")]
    PeerOverloaded,
    #[error("OAuth token is malformed")]
    MalformedToken,
    #[error("OAuth token header is not allowed")]
    InvalidHeader,
    #[error("OAuth token signing key is unavailable")]
    KeyUnavailable,
    #[error("OAuth token signature is invalid")]
    InvalidSignature,
    #[error("OAuth token claims are invalid")]
    InvalidClaims,
    #[error("OAuth provider metadata is invalid")]
    InvalidMetadata,
    #[error("OAuth provider response is invalid")]
    InvalidResponse,
    #[error("OAuth provider request failed")]
    ProviderUnavailable,
    #[error("OAuth provider request timed out")]
    Timeout,
    #[error("OAuth provider response exceeds the size limit")]
    ResponseTooLarge,
    #[error("OAuth runtime configuration is invalid")]
    Configuration,
}

pub struct OAuthRuntime {
    config: OAuth,
    client: Client,
    client_secret: Option<ClientSecret>,
    metadata: Mutex<Option<Cached<Metadata>>>,
    jwks: Mutex<JwksState>,
    admission: Arc<OAuthAdmission>,
}

impl fmt::Debug for OAuthRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthRuntime")
            .field("mode", &self.config.mode)
            .field("issuer", &self.config.issuer)
            .field("client_secret", &self.client_secret)
            .finish_non_exhaustive()
    }
}

impl OAuthRuntime {
    pub fn new(config: OAuth) -> Result<Self, Error> {
        Self::new_with_admission(config, Arc::clone(&ADMISSION))
    }

    fn new_with_admission(config: OAuth, admission: Arc<OAuthAdmission>) -> Result<Self, Error> {
        let client_secret = if config.mode == OAuthMode::Introspection {
            Some(ClientSecret::new(
                config
                    .resolve_client_secret()
                    .map_err(|_| Error::Configuration)?,
            ))
        } else {
            None
        };

        let mut builder = Client::builder()
            .redirect(redirect::Policy::none())
            .no_proxy();
        if let Some(path) = &config.ca_certificate {
            for certificate in custom_ca_certificates(path)? {
                builder = builder.add_root_certificate(certificate);
            }
        }

        Ok(Self {
            config,
            client: builder.build().map_err(|_| Error::Configuration)?,
            client_secret,
            metadata: Mutex::new(None),
            jwks: Mutex::new(JwksState::default()),
            admission,
        })
    }

    /// Apply this generation's concurrency ceiling to future validation attempts.
    pub fn activate_limit(&self) {
        self.admission
            .set_limit(self.config.max_concurrent_requests());
    }

    pub async fn validate(&self, token: &str, username: &str, peer: IpAddr) -> Result<(), Error> {
        let _permit = self.admission.try_acquire(peer)?;
        let deadline = Instant::now() + self.config.http_timeout();

        match self.config.mode {
            OAuthMode::Jwt => jwt::validate(self, token, username, deadline).await,
            OAuthMode::Introspection => {
                introspection::validate(self, token, username, deadline).await
            }
        }
    }

    pub fn config(&self) -> &OAuth {
        &self.config
    }

    async fn metadata(&self, deadline: Instant) -> Result<Metadata, Error> {
        let now = Instant::now();
        let mut cached = self.metadata.lock().await;
        if let Some(metadata) = cached.as_ref().and_then(|cached| cached.get(now)) {
            return Ok(metadata.clone());
        }

        let url = self
            .config
            .discovery_url()
            .map_err(|_| Error::Configuration)?;
        let value = self.get_json(url, deadline).await?;
        let metadata: Metadata =
            serde_json::from_value(value).map_err(|_| Error::InvalidMetadata)?;
        if metadata.issuer != self.config.issuer {
            return Err(Error::InvalidMetadata);
        }

        *cached = Some(Cached::new(
            metadata.clone(),
            self.config.discovery_cache_ttl(),
            Instant::now(),
        ));
        Ok(metadata)
    }

    async fn jwks(
        &self,
        deadline: Instant,
        force_refresh: bool,
    ) -> Result<jsonwebtoken::jwk::JwkSet, Error> {
        let metadata = self.metadata(deadline).await?;
        let uri = self.jwt_endpoint(&metadata)?;
        let now = Instant::now();
        let mut state = self.jwks.lock().await;

        if force_refresh {
            if state
                .last_unknown_kid_refresh
                .is_some_and(|last| now.duration_since(last) < UNKNOWN_KID_REFRESH_COOLDOWN)
            {
                return state
                    .cached
                    .as_ref()
                    .filter(|cached| cached.uri == uri)
                    .and_then(|cached| cached.value.get(now))
                    .cloned()
                    .ok_or(Error::KeyUnavailable);
            }
            state.last_unknown_kid_refresh = Some(now);
        } else if let Some(keys) = state
            .cached
            .as_ref()
            .filter(|cached| cached.uri == uri)
            .and_then(|cached| cached.value.get(now))
        {
            return Ok(keys.clone());
        }

        let value = self.get_json(uri.clone(), deadline).await?;
        let keys: jsonwebtoken::jwk::JwkSet =
            serde_json::from_value(value).map_err(|_| Error::InvalidResponse)?;
        if keys.keys.len() > MAX_JWKS_KEYS {
            return Err(Error::InvalidResponse);
        }

        state.cached = Some(CachedJwks {
            uri,
            value: Cached::new(keys.clone(), self.config.jwks_cache_ttl(), Instant::now()),
        });
        Ok(keys)
    }

    async fn introspection_endpoint(&self, deadline: Instant) -> Result<Url, Error> {
        let metadata = self.metadata(deadline).await?;
        let endpoint_url = self
            .config
            .introspection_endpoint
            .as_deref()
            .or(metadata.introspection_endpoint.as_deref())
            .ok_or(Error::InvalidMetadata)?;
        endpoint(
            &self.config,
            endpoint_url,
            self.config.introspection_endpoint.as_deref(),
        )
    }

    fn jwt_endpoint(&self, metadata: &Metadata) -> Result<Url, Error> {
        let endpoint_url = self
            .config
            .jwks_uri
            .as_deref()
            .or(metadata.jwks_uri.as_deref())
            .ok_or(Error::InvalidMetadata)?;
        endpoint(&self.config, endpoint_url, self.config.jwks_uri.as_deref())
    }

    async fn get_json(&self, url: Url, deadline: Instant) -> Result<Value, Error> {
        let response = self.send(self.client.get(url), deadline).await?;
        let body = read_body(response, deadline).await?;
        unique_json(&body)
    }

    async fn send(&self, request: RequestBuilder, deadline: Instant) -> Result<Response, Error> {
        let response = tokio::time::timeout_at(deadline, request.send())
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::ProviderUnavailable)?;
        if !response.status().is_success() {
            return Err(Error::ProviderUnavailable);
        }
        Ok(response)
    }
}

#[derive(Clone, Deserialize)]
struct Metadata {
    issuer: String,
    jwks_uri: Option<String>,
    introspection_endpoint: Option<String>,
}

#[derive(Clone)]
struct Cached<T> {
    value: T,
    expires_at: Instant,
}

impl<T> Cached<T> {
    fn new(value: T, ttl: Duration, now: Instant) -> Self {
        Self {
            value,
            expires_at: now + ttl,
        }
    }

    fn get(&self, now: Instant) -> Option<&T> {
        (now < self.expires_at).then_some(&self.value)
    }
}

#[derive(Default)]
struct JwksState {
    cached: Option<CachedJwks>,
    last_unknown_kid_refresh: Option<Instant>,
}

struct CachedJwks {
    uri: Url,
    value: Cached<jsonwebtoken::jwk::JwkSet>,
}

pub struct OAuthAdmission {
    state: ParkingMutex<AdmissionState>,
}

struct AdmissionState {
    limit: usize,
    active: usize,
    peers: HashMap<IpAddr, usize>,
}

impl OAuthAdmission {
    fn new(limit: usize) -> Self {
        Self {
            state: ParkingMutex::new(AdmissionState {
                limit,
                active: 0,
                peers: HashMap::new(),
            }),
        }
    }

    pub fn set_limit(&self, limit: usize) {
        self.state.lock().limit = limit;
    }

    fn try_acquire(self: &Arc<Self>, peer: IpAddr) -> Result<AdmissionGuard, Error> {
        let mut state = self.state.lock();
        if state.active >= state.limit {
            return Err(Error::Overloaded);
        }
        let peer_limit = state.limit.min(8);
        if state.peers.get(&peer).copied().unwrap_or_default() >= peer_limit {
            return Err(Error::PeerOverloaded);
        }

        state.active += 1;
        *state.peers.entry(peer).or_default() += 1;
        drop(state);
        Ok(AdmissionGuard {
            admission: Arc::clone(self),
            peer,
        })
    }
}

struct AdmissionGuard {
    admission: Arc<OAuthAdmission>,
    peer: IpAddr,
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        let mut state = self.admission.state.lock();
        state.active -= 1;
        let count = state
            .peers
            .get_mut(&self.peer)
            .expect("admission guard always owns a peer permit");
        *count -= 1;
        if *count == 0 {
            state.peers.remove(&self.peer);
        }
    }
}

fn custom_ca_certificates(path: &Path) -> Result<Vec<reqwest::tls::Certificate>, Error> {
    let pem = std::fs::read(path).map_err(|_| Error::Configuration)?;
    reqwest::tls::Certificate::from_pem_bundle(&pem).map_err(|_| Error::Configuration)
}

fn endpoint(config: &OAuth, value: &str, exact_override: Option<&str>) -> Result<Url, Error> {
    let url = Url::parse(value).map_err(|_| Error::InvalidMetadata)?;
    if url.scheme() != "https"
        || url.host().is_none()
        || url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::InvalidMetadata);
    }

    let issuer = Url::parse(&config.issuer).map_err(|_| Error::Configuration)?;
    let approved = exact_override.is_some_and(|approved| approved == value);
    if !approved && url.origin() != issuer.origin() {
        return Err(Error::InvalidMetadata);
    }
    Ok(url)
}

fn validate_common_claims(
    claims: &Map<String, Value>,
    config: &OAuth,
    username: &str,
) -> Result<(), Error> {
    let audience = claims.get("aud").ok_or(Error::InvalidClaims)?;
    let audience_matches = match audience {
        Value::String(audience) => audience == &config.audience,
        Value::Array(audiences) => {
            audiences.iter().all(Value::is_string)
                && audiences
                    .iter()
                    .any(|audience| audience.as_str() == Some(config.audience.as_str()))
        }
        _ => false,
    };
    if !audience_matches {
        return Err(Error::InvalidClaims);
    }

    let scope = claims.get("scope").map(normalize_scope).transpose()?;
    let scp = claims.get("scp").map(normalize_scope).transpose()?;
    let scopes = match (scope, scp) {
        (Some(scope), Some(scp)) if scope != scp => return Err(Error::InvalidClaims),
        (Some(scope), _) => scope,
        (_, Some(scp)) => scp,
        (None, None) => return Err(Error::InvalidClaims),
    };
    if !config.scopes.iter().all(|scope| scopes.contains(scope)) {
        return Err(Error::InvalidClaims);
    }

    if claims.get(config.identity_claim()).and_then(Value::as_str) != Some(username) {
        return Err(Error::InvalidClaims);
    }

    Ok(())
}

fn normalize_scope(value: &Value) -> Result<std::collections::HashSet<String>, Error> {
    match value {
        Value::String(scopes) => Ok(scopes.split_ascii_whitespace().map(str::to_owned).collect()),
        Value::Array(scopes) => scopes
            .iter()
            .map(|scope| {
                scope
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(Error::InvalidClaims)
            })
            .collect(),
        _ => Err(Error::InvalidClaims),
    }
}

async fn read_body(mut response: Response, deadline: Instant) -> Result<Vec<u8>, Error> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PROVIDER_BODY_LEN as u64)
    {
        return Err(Error::ResponseTooLarge);
    }

    let mut body = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or_default()
            .min(MAX_PROVIDER_BODY_LEN as u64) as usize,
    );
    loop {
        let chunk = tokio::time::timeout_at(deadline, response.chunk())
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::ProviderUnavailable)?;
        let Some(chunk) = chunk else {
            break;
        };
        if body.len() + chunk.len() > MAX_PROVIDER_BODY_LEN {
            return Err(Error::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn unique_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    let value: UniqueValue = serde_json::from_slice(bytes).map_err(|_| Error::InvalidResponse)?;
    serde_json::from_value(value.0).map_err(|_| Error::InvalidResponse)
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("valid JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        UniqueValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some((key, value)) = object.next_entry::<String, UniqueValue>()? {
            if values.insert(key, value.0).is_some() {
                return Err(A::Error::custom("duplicate JSON object key"));
            }
        }
        Ok(UniqueValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod test;
