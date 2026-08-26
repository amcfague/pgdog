use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::jwk::{
    AlgorithmParameters, EllipticCurve, Jwk, JwkSet, KeyOperations, PublicKeyUse,
};
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode};
use pgdog_config::{OAuth, OAuthAlgorithm};
use serde_json::{Map, Value};
use tokio::time::Instant;

use super::{Error, OAuthRuntime, unique_json, validate_common_claims};

pub(super) struct ParsedToken {
    header: Header,
    claims: Map<String, Value>,
}

pub(super) async fn validate(
    runtime: &OAuthRuntime,
    token: &str,
    username: &str,
    deadline: Instant,
) -> Result<(), Error> {
    let parsed = parse(token, &runtime.config)?;
    let mut keys = runtime.jwks(deadline, false).await?;
    let key = match select_key(&keys, &parsed.header) {
        Ok(key) => key,
        Err(Error::KeyUnavailable) => {
            keys = runtime.jwks(deadline, true).await?;
            select_key(&keys, &parsed.header)?
        }
        Err(error) => return Err(error),
    };
    verify(token, username, &runtime.config, &parsed, key)
}

#[cfg(test)]
pub(super) fn validate_with_keys(
    token: &str,
    username: &str,
    config: &OAuth,
    keys: &JwkSet,
) -> Result<(), Error> {
    let parsed = parse(token, config)?;
    let key = select_key(keys, &parsed.header)?;
    verify(token, username, config, &parsed, key)
}

pub(super) fn parse(token: &str, config: &OAuth) -> Result<ParsedToken, Error> {
    let mut parts = token.split('.');
    let (Some(encoded_header), Some(encoded_claims), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::MalformedToken);
    };

    let header_value = unique_segment(encoded_header)?;
    let claims_value = unique_segment(encoded_claims)?;
    let header: Header = serde_json::from_value(header_value).map_err(|_| Error::InvalidHeader)?;
    let claims = claims_value
        .as_object()
        .cloned()
        .ok_or(Error::InvalidClaims)?;

    if header.typ.as_deref() != Some("at+jwt")
        || header.kid.as_deref().is_none_or(str::is_empty)
        || header.jku.is_some()
        || header.jwk.is_some()
        || header.x5u.is_some()
        || header.x5c.is_some()
        || header.crit.as_ref().is_some_and(|crit| !crit.is_empty())
        || !config
            .algorithms()
            .iter()
            .any(|configured| algorithm(*configured) == header.alg)
    {
        return Err(Error::InvalidHeader);
    }

    Ok(ParsedToken { header, claims })
}

fn unique_segment(segment: &str) -> Result<Value, Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| Error::MalformedToken)?;
    unique_json(&bytes).map_err(|_| Error::MalformedToken)
}

fn select_key<'a>(keys: &'a JwkSet, header: &Header) -> Result<&'a Jwk, Error> {
    let kid = header.kid.as_deref().ok_or(Error::InvalidHeader)?;
    let mut matches = keys
        .keys
        .iter()
        .filter(|key| key.common.key_id.as_deref() == Some(kid));
    let key = matches.next().ok_or(Error::KeyUnavailable)?;
    if matches.next().is_some() {
        return Err(Error::InvalidResponse);
    }

    if key
        .common
        .public_key_use
        .as_ref()
        .is_some_and(|usage| usage != &PublicKeyUse::Signature)
        || key
            .common
            .key_operations
            .as_ref()
            .is_some_and(|operations| !operations.contains(&KeyOperations::Verify))
        || key
            .common
            .key_algorithm
            .and_then(|key_algorithm| Algorithm::try_from(key_algorithm).ok())
            != Some(header.alg)
        || !compatible_parameters(header.alg, &key.algorithm)
    {
        return Err(Error::InvalidResponse);
    }

    Ok(key)
}

fn compatible_parameters(algorithm: Algorithm, parameters: &AlgorithmParameters) -> bool {
    match (algorithm, parameters) {
        (
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512,
            AlgorithmParameters::RSA(_),
        ) => true,
        (Algorithm::ES256, AlgorithmParameters::EllipticCurve(parameters)) => {
            parameters.curve == EllipticCurve::P256
        }
        (Algorithm::ES384, AlgorithmParameters::EllipticCurve(parameters)) => {
            parameters.curve == EllipticCurve::P384
        }
        (Algorithm::EdDSA, AlgorithmParameters::OctetKeyPair(parameters)) => {
            parameters.curve == EllipticCurve::Ed25519
        }
        _ => false,
    }
}

fn verify(
    token: &str,
    username: &str,
    config: &OAuth,
    parsed: &ParsedToken,
    key: &Jwk,
) -> Result<(), Error> {
    let key = DecodingKey::from_jwk(key).map_err(|_| Error::InvalidResponse)?;
    let mut validation = Validation::new(parsed.header.alg);
    validation.leeway = config.clock_skew().as_secs();
    validation.validate_nbf = true;
    validation.set_audience(&[&config.audience]);
    validation.set_issuer(&[&config.issuer]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);

    decode::<Value>(token, &key, &validation).map_err(|error| {
        if matches!(
            error.kind(),
            jsonwebtoken::errors::ErrorKind::InvalidSignature
        ) {
            Error::InvalidSignature
        } else {
            Error::InvalidClaims
        }
    })?;

    validate_common_claims(&parsed.claims, config, username)
}

fn algorithm(algorithm: OAuthAlgorithm) -> Algorithm {
    match algorithm {
        OAuthAlgorithm::Rs256 => Algorithm::RS256,
        OAuthAlgorithm::Rs384 => Algorithm::RS384,
        OAuthAlgorithm::Rs512 => Algorithm::RS512,
        OAuthAlgorithm::Ps256 => Algorithm::PS256,
        OAuthAlgorithm::Ps384 => Algorithm::PS384,
        OAuthAlgorithm::Ps512 => Algorithm::PS512,
        OAuthAlgorithm::Es256 => Algorithm::ES256,
        OAuthAlgorithm::Es384 => Algorithm::ES384,
        OAuthAlgorithm::EdDsa => Algorithm::EdDSA,
    }
}
