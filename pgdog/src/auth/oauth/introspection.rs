use std::collections::BTreeMap;

use oauth2::{
    ExtraTokenFields, StandardTokenIntrospectionResponse, TokenIntrospectionResponse,
    basic::BasicTokenType,
};
use pgdog_config::OAuth;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::time::Instant;

use super::{Error, OAuthRuntime, read_body, unique_json, validate_common_claims};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct ExtraFields {
    #[serde(flatten)]
    fields: BTreeMap<String, Value>,
}

impl ExtraTokenFields for ExtraFields {}

type IntrospectionResponse = StandardTokenIntrospectionResponse<ExtraFields, BasicTokenType>;

pub(super) async fn validate(
    runtime: &OAuthRuntime,
    token: &str,
    username: &str,
    deadline: Instant,
) -> Result<(), Error> {
    let endpoint = runtime.introspection_endpoint(deadline).await?;
    let client_id = runtime
        .config
        .client_id
        .as_deref()
        .ok_or(Error::Configuration)?;
    let client_secret = runtime.client_secret.as_ref().ok_or(Error::Configuration)?;
    let request = runtime
        .client
        .post(endpoint)
        .basic_auth(client_id, Some(client_secret.secret()))
        .form(&[("token", token), ("token_type_hint", "access_token")]);
    let response = runtime.send(request, deadline).await?;
    let body = read_body(response, deadline).await?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::InvalidResponse)?
        .as_secs();

    validate_response(&body, &runtime.config, username, now)
}

pub(super) fn validate_response(
    body: &[u8],
    config: &OAuth,
    username: &str,
    now: u64,
) -> Result<(), Error> {
    let value: Value = unique_json(body)?;
    let claims = value.as_object().ok_or(Error::InvalidResponse)?;
    let response: IntrospectionResponse =
        serde_json::from_value(value.clone()).map_err(|_| Error::InvalidResponse)?;

    if !response.active()
        || response.token_type() != Some(&BasicTokenType::Bearer)
        || response.iss() != Some(config.issuer.as_str())
    {
        return Err(Error::InvalidClaims);
    }

    let skew = config.clock_skew().as_secs();
    if let Some(expiration) = response.exp() {
        let expiration: u64 = expiration
            .timestamp()
            .try_into()
            .map_err(|_| Error::InvalidClaims)?;
        if expiration.saturating_add(skew) <= now {
            return Err(Error::InvalidClaims);
        }
    }
    if let Some(not_before) = response.nbf() {
        let not_before: u64 = not_before
            .timestamp()
            .try_into()
            .map_err(|_| Error::InvalidClaims)?;
        if not_before > now.saturating_add(skew) {
            return Err(Error::InvalidClaims);
        }
    }

    validate_common_claims(claims, config, username)
}
