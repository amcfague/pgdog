//! OAuth authentication settings.

use std::env::{self, VarError};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{Error, General, PassthroughAuth};

pub const DEFAULT_HTTP_TIMEOUT_MS: u64 = 5_000;
pub const DEFAULT_CLOCK_SKEW_MS: u64 = 60_000;
pub const MAX_CLOCK_SKEW_MS: u64 = 300_000;
pub const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 64;
pub const MAX_CONCURRENT_REQUESTS: usize = 1_024;
pub const DEFAULT_JWKS_CACHE_TTL_MS: u64 = 300_000;
pub const MAX_JWKS_CACHE_TTL_MS: u64 = 3_600_000;
pub const DISCOVERY_CACHE_TTL_MS: u64 = 300_000;
pub const MAX_CLIENT_SECRET_BYTES: u64 = 64 * 1024;
pub const CLIENT_SECRET_ENV: &str = "PGDOG_OAUTH_CLIENT_SECRET";

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OAuthMode {
    Jwt,
    Introspection,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, JsonSchema)]
pub enum OAuthAlgorithm {
    #[serde(rename = "RS256")]
    Rs256,
    #[serde(rename = "RS384")]
    Rs384,
    #[serde(rename = "RS512")]
    Rs512,
    #[serde(rename = "PS256")]
    Ps256,
    #[serde(rename = "PS384")]
    Ps384,
    #[serde(rename = "PS512")]
    Ps512,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "ES384")]
    Es384,
    #[serde(rename = "EdDSA")]
    EdDsa,
}

const DEFAULT_ALGORITHMS: &[OAuthAlgorithm] = &[OAuthAlgorithm::Rs256];

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OAuth {
    pub mode: OAuthMode,
    pub issuer: String,
    pub audience: String,
    pub scopes: Vec<String>,
    pub identity_claim: Option<String>,
    pub discovery_url: Option<String>,
    pub http_timeout: Option<u64>,
    pub clock_skew: Option<u64>,
    pub ca_certificate: Option<PathBuf>,
    pub max_concurrent_requests: Option<usize>,
    pub algorithms: Option<Vec<OAuthAlgorithm>>,
    pub jwks_uri: Option<String>,
    pub jwks_cache_ttl: Option<u64>,
    pub introspection_endpoint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret_file: Option<PathBuf>,
}

impl OAuth {
    pub fn identity_claim(&self) -> &str {
        self.identity_claim.as_deref().unwrap_or("sub")
    }

    pub fn http_timeout(&self) -> Duration {
        Duration::from_millis(self.http_timeout.unwrap_or(DEFAULT_HTTP_TIMEOUT_MS))
    }

    pub fn clock_skew(&self) -> Duration {
        Duration::from_millis(self.clock_skew.unwrap_or(DEFAULT_CLOCK_SKEW_MS))
    }

    pub fn max_concurrent_requests(&self) -> usize {
        self.max_concurrent_requests
            .unwrap_or(DEFAULT_MAX_CONCURRENT_REQUESTS)
    }

    pub fn algorithms(&self) -> &[OAuthAlgorithm] {
        self.algorithms.as_deref().unwrap_or(DEFAULT_ALGORITHMS)
    }

    pub fn jwks_cache_ttl(&self) -> Duration {
        Duration::from_millis(self.jwks_cache_ttl.unwrap_or(DEFAULT_JWKS_CACHE_TTL_MS))
    }

    pub fn discovery_cache_ttl(&self) -> Duration {
        Duration::from_millis(DISCOVERY_CACHE_TTL_MS)
    }

    pub fn discovery_url(&self) -> Result<Url, Error> {
        if let Some(url) = &self.discovery_url {
            return validate_https_url("discovery_url", url);
        }

        validate_https_url(
            "discovery_url",
            &format!(
                "{}/.well-known/openid-configuration",
                self.issuer.trim_end_matches('/')
            ),
        )
    }

    pub(crate) fn validate(&self, general: &General) -> Result<(), Error> {
        let secret = if self.mode == OAuthMode::Introspection {
            secret_from_env()?
        } else {
            None
        };

        self.validate_with_secret_env(general, secret.as_deref())
    }

    /// Resolve and normalize the configured introspection client secret.
    pub fn resolve_client_secret(&self) -> Result<String, Error> {
        let secret = secret_from_env()?;
        self.resolve_client_secret_with_env(secret.as_deref())
    }

    fn validate_with_secret_env(
        &self,
        general: &General,
        secret_env: Option<&str>,
    ) -> Result<(), Error> {
        if self.issuer.trim().is_empty() {
            return Err(parse_error("oauth issuer must not be empty"));
        }
        if self.audience.trim().is_empty() {
            return Err(parse_error("oauth audience must not be empty"));
        }
        if self.scopes.is_empty() || self.scopes.iter().any(|scope| scope.trim().is_empty()) {
            return Err(parse_error("oauth scopes must not be empty"));
        }
        if self.identity_claim().trim().is_empty() {
            return Err(parse_error("oauth identity_claim must not be empty"));
        }

        let issuer = validate_https_url("issuer", &self.issuer)?;
        if issuer.query().is_some() {
            return Err(parse_error("oauth issuer must not contain a query"));
        }
        self.discovery_url()?;

        if self.http_timeout().is_zero() {
            return Err(parse_error("oauth http_timeout must be positive"));
        }
        if self.http_timeout() >= Duration::from_millis(general.client_login_timeout) {
            return Err(parse_error(
                "oauth http_timeout must be less than general.client_login_timeout",
            ));
        }
        if self.clock_skew() > Duration::from_millis(MAX_CLOCK_SKEW_MS) {
            return Err(parse_error(format!(
                "oauth clock_skew must not exceed {MAX_CLOCK_SKEW_MS} milliseconds"
            )));
        }
        if !(1..=MAX_CONCURRENT_REQUESTS).contains(&self.max_concurrent_requests()) {
            return Err(parse_error(format!(
                "oauth max_concurrent_requests must be between 1 and {MAX_CONCURRENT_REQUESTS}"
            )));
        }

        if !general.tls_client_required {
            return Err(parse_error(
                "general.tls_client_required must be true when auth_type is oauth",
            ));
        }
        let certificate = general.tls_certificate.as_deref().ok_or_else(|| {
            parse_error("general.tls_certificate is required when auth_type is oauth")
        })?;
        let private_key = general.tls_private_key.as_deref().ok_or_else(|| {
            parse_error("general.tls_private_key is required when auth_type is oauth")
        })?;
        readable_file("general.tls_certificate", certificate)?;
        readable_file("general.tls_private_key", private_key)?;
        if general.passthrough_auth != PassthroughAuth::Disabled {
            return Err(parse_error(
                "general.passthrough_auth must be disabled when auth_type is oauth",
            ));
        }
        if let Some(path) = &self.ca_certificate {
            readable_file("oauth ca_certificate", path)?;
        }

        match self.mode {
            OAuthMode::Jwt => self.validate_jwt(),
            OAuthMode::Introspection => self.validate_introspection(secret_env),
        }
    }

    fn validate_jwt(&self) -> Result<(), Error> {
        if self.algorithms().is_empty() {
            return Err(parse_error("oauth algorithms must not be empty"));
        }
        if self.jwks_cache_ttl().is_zero()
            || self.jwks_cache_ttl() > Duration::from_millis(MAX_JWKS_CACHE_TTL_MS)
        {
            return Err(parse_error(format!(
                "oauth jwks_cache_ttl must be between 1 and {MAX_JWKS_CACHE_TTL_MS} milliseconds"
            )));
        }
        if let Some(url) = &self.jwks_uri {
            validate_https_url("jwks_uri", url)?;
        }
        if self.introspection_endpoint.is_some()
            || self.client_id.is_some()
            || self.client_secret_file.is_some()
        {
            return Err(parse_error(
                "oauth JWT mode cannot contain introspection-only fields",
            ));
        }

        Ok(())
    }

    fn validate_introspection(&self, secret_env: Option<&str>) -> Result<(), Error> {
        if self.algorithms.is_some() || self.jwks_uri.is_some() || self.jwks_cache_ttl.is_some() {
            return Err(parse_error(
                "oauth introspection mode cannot contain JWT-only fields",
            ));
        }
        if self
            .client_id
            .as_deref()
            .is_none_or(|id| id.trim().is_empty())
        {
            return Err(parse_error(
                "oauth client_id is required in introspection mode",
            ));
        }
        if let Some(url) = &self.introspection_endpoint {
            validate_https_url("introspection_endpoint", url)?;
        }
        self.resolve_client_secret_with_env(secret_env)?;

        Ok(())
    }

    fn resolve_client_secret_with_env(&self, secret_env: Option<&str>) -> Result<String, Error> {
        let secret_env = secret_env.filter(|secret| !secret.is_empty());
        match (&self.client_secret_file, secret_env) {
            (Some(_), Some(_)) => Err(parse_error(format!(
                "configure exactly one non-empty OAuth client secret source: client_secret_file or {CLIENT_SECRET_ENV}"
            ))),
            (Some(path), None) => read_secret(path),
            (None, Some(secret)) => normalize_secret(secret.to_owned()),
            (None, None) => Err(parse_error(format!(
                "an OAuth client secret is required through client_secret_file or {CLIENT_SECRET_ENV}"
            ))),
        }
    }
}

fn secret_from_env() -> Result<Option<String>, Error> {
    match env::var(CLIENT_SECRET_ENV) {
        Ok(secret) => Ok(Some(secret)),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => Err(parse_error(format!(
            "{CLIENT_SECRET_ENV} must contain valid UTF-8"
        ))),
    }
}

fn validate_https_url(name: &str, value: &str) -> Result<Url, Error> {
    let url = Url::parse(value)
        .map_err(|error| parse_error(format!("oauth {name} is invalid: {error}")))?;
    if url.scheme() != "https" || url.host().is_none() || url.cannot_be_a_base() {
        return Err(parse_error(format!(
            "oauth {name} must be an absolute HTTPS URL"
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(parse_error(format!(
            "oauth {name} must not contain credentials"
        )));
    }
    if url.fragment().is_some() {
        return Err(parse_error(format!(
            "oauth {name} must not contain a fragment"
        )));
    }

    Ok(url)
}

fn readable_file(name: &str, path: &Path) -> Result<(), Error> {
    File::open(path).map_err(|error| {
        parse_error(format!(
            "{name} must reference a readable file at {}: {error}",
            path.display()
        ))
    })?;
    Ok(())
}

fn read_secret(path: &Path) -> Result<String, Error> {
    let file = File::open(path).map_err(|error| {
        parse_error(format!(
            "oauth client_secret_file is not readable at {}: {error}",
            path.display()
        ))
    })?;
    let mut bytes = Vec::new();
    file.take(MAX_CLIENT_SECRET_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            parse_error(format!(
                "oauth client_secret_file could not be read at {}: {error}",
                path.display()
            ))
        })?;
    if bytes.len() as u64 > MAX_CLIENT_SECRET_BYTES {
        return Err(parse_error(format!(
            "oauth client_secret_file must not exceed {MAX_CLIENT_SECRET_BYTES} bytes"
        )));
    }
    let secret = String::from_utf8(bytes)
        .map_err(|_| parse_error("oauth client_secret_file must contain valid UTF-8"))?;
    normalize_secret(secret)
}

fn normalize_secret(mut secret: String) -> Result<String, Error> {
    if secret.ends_with('\n') {
        secret.pop();
        if secret.ends_with('\r') {
            secret.pop();
        }
    }
    if secret.is_empty() {
        return Err(parse_error("oauth client secret must not be empty"));
    }
    if secret.len() as u64 > MAX_CLIENT_SECRET_BYTES {
        return Err(parse_error(format!(
            "oauth client secret must not exceed {MAX_CLIENT_SECRET_BYTES} bytes"
        )));
    }
    if secret.contains('\0') {
        return Err(parse_error("oauth client secret must not contain NUL"));
    }

    Ok(secret)
}

fn parse_error(message: impl Into<String>) -> Error {
    Error::ParseError(message.into())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::str::FromStr;
    use std::time::Duration;

    use tempfile::TempDir;

    use super::*;
    use crate::{AuthType, Config, ConfigAndUsers, General, PassthroughAuth};

    fn write_file(dir: &TempDir, name: &str, contents: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, contents).unwrap();
        path
    }

    fn active_general(dir: &TempDir) -> General {
        General {
            auth_type: AuthType::OAuth,
            tls_client_required: true,
            tls_certificate: Some(write_file(dir, "client.crt", "certificate")),
            tls_private_key: Some(write_file(dir, "client.key", "private key")),
            client_login_timeout: 10_000,
            ..Default::default()
        }
    }

    fn oauth(mode: OAuthMode) -> OAuth {
        OAuth {
            mode,
            issuer: "https://issuer.example/tenant".into(),
            audience: "postgres".into(),
            scopes: vec!["openid".into(), "db.connect".into()],
            identity_claim: None,
            discovery_url: None,
            http_timeout: None,
            clock_skew: None,
            ca_certificate: None,
            max_concurrent_requests: None,
            algorithms: None,
            jwks_uri: None,
            jwks_cache_ttl: None,
            introspection_endpoint: None,
            client_id: None,
            client_secret_file: None,
        }
    }

    type OAuthMutation = Box<dyn Fn(&mut OAuth)>;

    fn error(oauth: &OAuth, general: &General, secret: Option<&str>) -> String {
        oauth
            .validate_with_secret_env(general, secret)
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn defaults_and_round_trip() {
        let config: Config = toml::from_str(
            r#"
[oauth]
mode = "jwt"
issuer = "https://issuer.example/tenant"
audience = "postgres"
scopes = ["openid", "db.connect"]
"#,
        )
        .unwrap();
        let oauth = config.oauth.as_ref().unwrap();

        assert_eq!(oauth.identity_claim(), "sub");
        assert_eq!(oauth.http_timeout(), Duration::from_millis(5_000));
        assert_eq!(oauth.clock_skew(), Duration::from_millis(60_000));
        assert_eq!(oauth.max_concurrent_requests(), 64);
        assert_eq!(oauth.algorithms(), &[OAuthAlgorithm::Rs256]);
        assert_eq!(oauth.jwks_cache_ttl(), Duration::from_millis(300_000));
        assert_eq!(oauth.discovery_cache_ttl(), Duration::from_millis(300_000));
        assert_eq!(
            oauth.discovery_url().unwrap().as_str(),
            "https://issuer.example/tenant/.well-known/openid-configuration"
        );

        let serialized = toml::to_string(&config).unwrap();
        assert!(!serialized.contains("client_secret"));
        let round_trip = toml::from_str::<Config>(&serialized).unwrap();
        assert_eq!(round_trip.oauth, config.oauth);
        assert_eq!(AuthType::from_str("oauth").unwrap(), AuthType::OAuth);
        assert_eq!(AuthType::OAuth.to_string(), "oauth");
    }

    #[test]
    fn validates_active_jwt_configuration() {
        let dir = TempDir::new().unwrap();
        let mut config = ConfigAndUsers::default();
        config.config.general = active_general(&dir);
        let mut oauth = oauth(OAuthMode::Jwt);
        oauth.clock_skew = Some(MAX_CLOCK_SKEW_MS);
        config.config.oauth = Some(oauth);

        config.check().unwrap();
    }

    #[test]
    fn active_oauth_requires_section_and_readable_tls_files() {
        let dir = TempDir::new().unwrap();
        let mut config = ConfigAndUsers::default();
        config.config.general = active_general(&dir);

        assert!(config.check().unwrap_err().to_string().contains("[oauth]"));

        config.config.oauth = Some(oauth(OAuthMode::Jwt));
        config.config.general.tls_certificate = Some(dir.path().join("missing.crt"));
        assert!(
            config
                .check()
                .unwrap_err()
                .to_string()
                .contains("tls_certificate")
        );
    }

    #[test]
    fn allows_cross_origin_exact_endpoint_overrides() {
        let dir = TempDir::new().unwrap();
        let general = active_general(&dir);
        let mut oauth = oauth(OAuthMode::Jwt);
        oauth.discovery_url = Some("https://metadata.example/oauth".into());
        oauth.jwks_uri = Some("https://keys.example/jwks".into());

        oauth.validate_with_secret_env(&general, None).unwrap();
    }

    #[test]
    fn rejects_unsafe_common_configuration() {
        let dir = TempDir::new().unwrap();
        let general = active_general(&dir);

        let cases: Vec<(&str, OAuthMutation)> = vec![
            ("issuer", Box::new(|o| o.issuer.clear())),
            ("audience", Box::new(|o| o.audience.clear())),
            ("scopes", Box::new(|o| o.scopes.clear())),
            (
                "identity_claim",
                Box::new(|o| o.identity_claim = Some("".into())),
            ),
            (
                "HTTPS",
                Box::new(|o| o.issuer = "http://issuer.example".into()),
            ),
            (
                "credentials",
                Box::new(|o| o.issuer = "https://user@issuer.example".into()),
            ),
            (
                "fragment",
                Box::new(|o| o.issuer = "https://issuer.example/#fragment".into()),
            ),
            ("http_timeout", Box::new(|o| o.http_timeout = Some(0))),
            (
                "client_login_timeout",
                Box::new(|o| o.http_timeout = Some(10_000)),
            ),
            ("clock_skew", Box::new(|o| o.clock_skew = Some(300_001))),
            (
                "max_concurrent_requests",
                Box::new(|o| o.max_concurrent_requests = Some(0)),
            ),
            (
                "max_concurrent_requests",
                Box::new(|o| o.max_concurrent_requests = Some(1_025)),
            ),
        ];

        for (expected, mutate) in cases {
            let mut candidate = oauth(OAuthMode::Jwt);
            mutate(&mut candidate);
            assert!(
                error(&candidate, &general, None).contains(expected),
                "missing {expected} in validation error"
            );
        }

        let mut no_tls = general.clone();
        no_tls.tls_client_required = false;
        assert!(error(&oauth(OAuthMode::Jwt), &no_tls, None).contains("tls_client_required"));

        let mut passthrough = general.clone();
        passthrough.passthrough_auth = PassthroughAuth::Enabled;
        assert!(error(&oauth(OAuthMode::Jwt), &passthrough, None).contains("passthrough_auth"));

        let mut unreadable = oauth(OAuthMode::Jwt);
        unreadable.ca_certificate = Some(dir.path().join("missing-ca.pem"));
        assert!(error(&unreadable, &general, None).contains("ca_certificate"));

        let mut bad_discovery = oauth(OAuthMode::Jwt);
        bad_discovery.discovery_url = Some("http://metadata.example".into());
        assert!(error(&bad_discovery, &general, None).contains("discovery_url"));

        let mut bad_jwks = oauth(OAuthMode::Jwt);
        bad_jwks.jwks_uri = Some("https://user@keys.example/jwks".into());
        assert!(error(&bad_jwks, &general, None).contains("jwks_uri"));
    }

    #[test]
    fn enforces_jwt_only_fields_and_bounds() {
        let dir = TempDir::new().unwrap();
        let general = active_general(&dir);

        let mut empty_algorithms = oauth(OAuthMode::Jwt);
        empty_algorithms.algorithms = Some(vec![]);
        assert!(error(&empty_algorithms, &general, None).contains("algorithms"));

        let mut excessive_ttl = oauth(OAuthMode::Jwt);
        excessive_ttl.jwks_cache_ttl = Some(3_600_001);
        assert!(error(&excessive_ttl, &general, None).contains("jwks_cache_ttl"));

        let mut conflict = oauth(OAuthMode::Jwt);
        conflict.client_id = Some("pgdog".into());
        assert!(error(&conflict, &general, None).contains("introspection-only"));

        assert!(
            toml::from_str::<OAuth>(
                r#"
mode = "jwt"
issuer = "https://issuer.example"
audience = "postgres"
scopes = ["openid"]
algorithms = ["HS256"]
"#
            )
            .is_err()
        );
    }

    #[test]
    fn validates_introspection_secret_sources() {
        let dir = TempDir::new().unwrap();
        let general = active_general(&dir);
        let mut oauth = oauth(OAuthMode::Introspection);
        oauth.client_id = Some("pgdog".into());

        assert!(error(&oauth, &general, None).contains("client secret"));
        oauth
            .validate_with_secret_env(&general, Some("secret"))
            .unwrap();
        assert!(error(&oauth, &general, Some("")).contains("client secret"));

        let secret_file = write_file(&dir, "client.secret", "from-file\n");
        oauth.client_secret_file = Some(secret_file);
        oauth.validate_with_secret_env(&general, None).unwrap();
        assert!(error(&oauth, &general, Some("from-env")).contains("exactly one"));

        fs::write(oauth.client_secret_file.as_ref().unwrap(), "").unwrap();
        assert!(error(&oauth, &general, None).contains("empty"));

        oauth.client_secret_file = Some(dir.path().join("missing.secret"));
        assert!(error(&oauth, &general, None).contains("not readable"));
    }

    #[test]
    fn rejects_introspection_mode_conflicts() {
        let dir = TempDir::new().unwrap();
        let general = active_general(&dir);
        let mut oauth = oauth(OAuthMode::Introspection);
        oauth.client_id = Some("pgdog".into());

        oauth.algorithms = Some(vec![OAuthAlgorithm::Rs256]);
        assert!(error(&oauth, &general, Some("secret")).contains("JWT-only"));

        oauth.algorithms = None;
        oauth.client_id = Some("".into());
        assert!(error(&oauth, &general, Some("secret")).contains("client_id"));
    }

    #[test]
    fn inactive_oauth_configuration_can_be_pre_staged() {
        let mut config = ConfigAndUsers::default();
        let mut candidate = oauth(OAuthMode::Introspection);
        candidate.client_id = Some("pgdog".into());
        config.config.oauth = Some(candidate);

        config.check().unwrap();
    }
}
