use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes as HyperBytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use jsonwebtoken::jwk::{Jwk, JwkSet, KeyOperations, PublicKeyUse};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use pgdog_config::{OAuth, OAuthAlgorithm, OAuthMode};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::*;

fn config(mode: OAuthMode) -> OAuth {
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
        max_concurrent_requests: Some(2),
        algorithms: None,
        jwks_uri: None,
        jwks_cache_ttl: None,
        introspection_endpoint: None,
        client_id: None,
        client_secret_file: None,
    }
}

fn jwt_material() -> (EncodingKey, JwkSet) {
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let encoding = EncodingKey::from_ed_der(key.as_ref());
    let mut jwk: Jwk = serde_json::from_value(json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
        "alg": "EdDSA",
    }))
    .unwrap();
    jwk.common.key_id = Some("key-1".into());
    jwk.common.public_key_use = Some(PublicKeyUse::Signature);
    jwk.common.key_operations = Some(vec![KeyOperations::Verify]);
    (encoding, JwkSet { keys: vec![jwk] })
}

fn jwt_token(key: &EncodingKey, typ: &str, subject: &str, issuer: &str) -> String {
    jwt_token_with_kid(key, typ, subject, issuer, "key-1")
}

fn jwt_token_with_kid(
    key: &EncodingKey,
    typ: &str,
    subject: &str,
    issuer: &str,
    kid: &str,
) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some(typ.into());
    header.kid = Some(kid.into());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    encode(
        &header,
        &json!({
            "iss": issuer,
            "aud": ["postgres"],
            "scope": "openid db.connect",
            "sub": subject,
            "exp": now + 60,
        }),
        key,
    )
    .unwrap()
}

struct MockIdp {
    issuer: String,
    jwks: String,
    metadata_requests: AtomicUsize,
    jwks_requests: AtomicUsize,
    introspection_requests: AtomicUsize,
    bad_basic_auth: AtomicBool,
    slow_metadata: AtomicBool,
    oversized_metadata: AtomicBool,
}

impl MockIdp {
    async fn response(
        self: Arc<Self>,
        request: Request<Incoming>,
    ) -> Result<Response<Full<HyperBytes>>, Infallible> {
        let path = request.uri().path().to_owned();
        let response = match path.as_str() {
            "/tenant/.well-known/openid-configuration" => {
                self.metadata_requests.fetch_add(1, Ordering::SeqCst);
                if self.slow_metadata.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                if self.oversized_metadata.load(Ordering::SeqCst) {
                    return Ok(Response::new(Full::new(HyperBytes::from(vec![
                        b'x';
                        MAX_PROVIDER_BODY_LEN
                            + 1
                    ]))));
                }
                json!({
                    "issuer": self.issuer,
                    "jwks_uri": format!("{}/jwks", self.issuer),
                    "introspection_endpoint": format!("{}/introspect", self.issuer),
                })
                .to_string()
            }
            "/tenant/jwks" => {
                self.jwks_requests.fetch_add(1, Ordering::SeqCst);
                self.jwks.clone()
            }
            "/tenant/introspect" => {
                self.introspection_requests.fetch_add(1, Ordering::SeqCst);
                let expected = format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode("pgdog:super-secret-value")
                );
                if request
                    .headers()
                    .get(hyper::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    != Some(expected.as_str())
                {
                    self.bad_basic_auth.store(true, Ordering::SeqCst);
                }
                let body = request.into_body().collect().await.unwrap().to_bytes();
                if !body
                    .windows(b"token=opaque".len())
                    .any(|part| part == b"token=opaque")
                    || !body
                        .windows(b"token_type_hint=access_token".len())
                        .any(|part| part == b"token_type_hint=access_token")
                {
                    self.bad_basic_auth.store(true, Ordering::SeqCst);
                }
                json!({
                    "active": true,
                    "token_type": "Bearer",
                    "iss": self.issuer,
                    "aud": "postgres",
                    "scope": "openid db.connect",
                    "sub": "alice",
                    "exp": 4_000_000_000u64,
                })
                .to_string()
            }
            _ => {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(HyperBytes::new()))
                    .unwrap());
            }
        };

        Ok(Response::new(Full::new(HyperBytes::from(response))))
    }
}

async fn mock_idp(
    jwks: &JwkSet,
) -> (
    Arc<MockIdp>,
    tokio::task::JoinHandle<()>,
    tempfile::TempDir,
    std::path::PathBuf,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!(
        "https://localhost:{}/tenant",
        listener.local_addr().unwrap().port()
    );
    let state = Arc::new(MockIdp {
        issuer,
        jwks: serde_json::to_string(jwks).unwrap(),
        metadata_requests: AtomicUsize::new(0),
        jwks_requests: AtomicUsize::new(0),
        introspection_requests: AtomicUsize::new(0),
        bad_basic_auth: AtomicBool::new(false),
        slow_metadata: AtomicBool::new(false),
        oversized_metadata: AtomicBool::new(false),
    });
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = cert.der().clone();
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let directory = tempfile::TempDir::new().unwrap();
    let ca_path = directory.path().join("ca.pem");
    std::fs::write(&ca_path, cert.pem()).unwrap();
    let tls = TlsAcceptor::from(Arc::new(
        tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key)
            .unwrap(),
    ));
    let server_state = Arc::clone(&state);
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let tls = tls.clone();
            let state = Arc::clone(&server_state);
            tokio::spawn(async move {
                let Ok(stream) = tls.accept(stream).await else {
                    return;
                };
                let service = service_fn(move |request| Arc::clone(&state).response(request));
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (state, task, directory, ca_path)
}

#[test]
fn jwt_requires_access_token_header_and_common_policy() {
    let mut config = config(OAuthMode::Jwt);
    config.algorithms = Some(vec![OAuthAlgorithm::EdDsa]);
    let (key, keys) = jwt_material();

    let valid = jwt_token(&key, "at+jwt", "alice", &config.issuer);
    jwt::validate_with_keys(&valid, "alice", &config, &keys).unwrap();

    let id_token = jwt_token(&key, "JWT", "alice", &config.issuer);
    assert!(matches!(
        jwt::validate_with_keys(&id_token, "alice", &config, &keys),
        Err(Error::InvalidHeader)
    ));

    let wrong_identity = jwt_token(&key, "at+jwt", "bob", &config.issuer);
    assert!(matches!(
        jwt::validate_with_keys(&wrong_identity, "alice", &config, &keys),
        Err(Error::InvalidClaims)
    ));
}

#[test]
fn jwt_rejects_duplicate_claims_and_embedded_keys() {
    let mut config = config(OAuthMode::Jwt);
    config.algorithms = Some(vec![OAuthAlgorithm::EdDsa]);
    let (key, keys) = jwt_material();
    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some("at+jwt".into());
    header.kid = Some("key-1".into());
    header.jwk = Some(keys.keys[0].clone());
    let embedded = encode(&header, &json!({"exp": 1}), &key).unwrap();
    assert!(matches!(
        jwt::validate_with_keys(&embedded, "alice", &config, &keys),
        Err(Error::InvalidHeader)
    ));

    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"at+jwt","kid":"key-1"}"#);
    let claims = URL_SAFE_NO_PAD.encode(
        br#"{"iss":"https://issuer.example/tenant","iss":"https://issuer.example/tenant","aud":"postgres","scope":"openid db.connect","sub":"alice","exp":9999999999}"#,
    );
    let duplicate = format!("{header}.{claims}.signature");
    assert!(matches!(
        jwt::parse(&duplicate, &config),
        Err(Error::MalformedToken)
    ));
}

#[test]
fn jwt_rejects_invalid_claims_and_key_metadata() {
    let mut config = config(OAuthMode::Jwt);
    config.algorithms = Some(vec![OAuthAlgorithm::EdDsa]);
    let (key, keys) = jwt_material();
    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some("at+jwt".into());
    header.kid = Some("key-1".into());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = |claims| encode(&header, &claims, &key).unwrap();

    let scp = token(json!({
        "iss": config.issuer.clone(),
        "aud": "postgres",
        "scp": ["openid", "db.connect"],
        "sub": "alice",
        "exp": now + 60,
    }));
    jwt::validate_with_keys(&scp, "alice", &config, &keys).unwrap();

    let missing_exp = token(json!({
        "iss": config.issuer.clone(),
        "aud": "postgres",
        "scope": "openid db.connect",
        "sub": "alice",
    }));
    assert!(matches!(
        jwt::validate_with_keys(&missing_exp, "alice", &config, &keys),
        Err(Error::InvalidClaims)
    ));

    let conflicting_scopes = token(json!({
        "iss": config.issuer.clone(),
        "aud": "postgres",
        "scope": "openid db.connect",
        "scp": ["openid"],
        "sub": "alice",
        "exp": now + 60,
    }));
    assert!(matches!(
        jwt::validate_with_keys(&conflicting_scopes, "alice", &config, &keys),
        Err(Error::InvalidClaims)
    ));

    let valid = jwt_token(&key, "at+jwt", "alice", &config.issuer);
    let mut encryption_key = keys.clone();
    encryption_key.keys[0].common.public_key_use = Some(PublicKeyUse::Encryption);
    assert!(matches!(
        jwt::validate_with_keys(&valid, "alice", &config, &encryption_key),
        Err(Error::InvalidResponse)
    ));

    let mut duplicate_key = keys.clone();
    duplicate_key.keys.push(duplicate_key.keys[0].clone());
    assert!(matches!(
        jwt::validate_with_keys(&valid, "alice", &config, &duplicate_key),
        Err(Error::InvalidResponse)
    ));
}

#[test]
fn limiter_applies_lowered_limit_to_new_work() {
    let admission = Arc::new(OAuthAdmission::new(2));
    let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let first = admission.try_acquire(peer).unwrap();
    let second = admission.try_acquire(peer).unwrap();

    admission.set_limit(1);
    assert!(matches!(
        admission.try_acquire(peer),
        Err(Error::Overloaded)
    ));
    drop(first);
    assert!(matches!(
        admission.try_acquire(peer),
        Err(Error::Overloaded)
    ));
    drop(second);
    assert!(admission.try_acquire(peer).is_ok());
}

#[test]
fn limiter_keeps_capacity_for_another_peer() {
    let admission = Arc::new(OAuthAdmission::new(16));
    let first_peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let second_peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    let permits = (0..8)
        .map(|_| admission.try_acquire(first_peer).unwrap())
        .collect::<Vec<_>>();

    assert!(matches!(
        admission.try_acquire(first_peer),
        Err(Error::PeerOverloaded)
    ));
    assert!(admission.try_acquire(second_peer).is_ok());
    drop(permits);
}

#[test]
fn strict_introspection_policy_requires_access_token_evidence() {
    let config = config(OAuthMode::Introspection);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let valid = format!(
        r#"{{"active":true,"token_type":"Bearer","iss":"https://issuer.example/tenant","aud":"postgres","scope":"openid db.connect","sub":"alice","exp":{}}}"#,
        now + 60
    );
    introspection::validate_response(valid.as_bytes(), &config, "alice", now).unwrap();

    for invalid in [
        valid.replace("\"active\":true", "\"active\":false"),
        valid.replace("\"iss\":\"https://issuer.example/tenant\",", ""),
        valid.replace("\"token_type\":\"Bearer\",", ""),
        valid.replace("\"token_type\":\"Bearer\"", "\"token_type\":\"MAC\""),
        valid.replace("\"sub\":\"alice\"", "\"sub\":\"bob\""),
    ] {
        assert!(
            introspection::validate_response(invalid.as_bytes(), &config, "alice", now).is_err()
        );
    }
}

#[test]
fn introspection_rejects_conflicting_scope_shapes_and_bad_times() {
    let config = config(OAuthMode::Introspection);
    let now = 1_000_000;
    let conflicting = br#"{"active":true,"token_type":"Bearer","iss":"https://issuer.example/tenant","aud":["postgres"],"scope":"openid db.connect","scp":["openid"],"sub":"alice"}"#;
    assert!(introspection::validate_response(conflicting, &config, "alice", now).is_err());

    let expired = format!(
        r#"{{"active":true,"token_type":"Bearer","iss":"https://issuer.example/tenant","aud":"postgres","scope":"openid db.connect","sub":"alice","exp":{}}}"#,
        now - config.clock_skew().as_secs() - 1
    );
    assert!(introspection::validate_response(expired.as_bytes(), &config, "alice", now).is_err());

    let future = format!(
        r#"{{"active":true,"token_type":"Bearer","iss":"https://issuer.example/tenant","aud":"postgres","scope":"openid db.connect","sub":"alice","nbf":{}}}"#,
        now + config.clock_skew().as_secs() + 1
    );
    assert!(introspection::validate_response(future.as_bytes(), &config, "alice", now).is_err());
}

#[test]
fn provider_json_rejects_duplicate_keys_at_any_depth() {
    assert!(unique_json::<serde_json::Value>(br#"{"a":{"x":1,"x":2}}"#).is_err());
}

#[test]
fn endpoint_policy_allows_only_approved_https_origins() {
    let config = config(OAuthMode::Jwt);
    assert!(endpoint(&config, "https://issuer.example/jwks", None).is_ok());
    assert!(endpoint(&config, "https://other.example/jwks", None).is_err());
    assert!(
        endpoint(
            &config,
            "https://other.example/jwks",
            Some("https://other.example/jwks"),
        )
        .is_ok()
    );
    assert!(endpoint(&config, "http://issuer.example/jwks", None).is_err());
    assert!(endpoint(&config, "https://user@issuer.example/jwks", None).is_err());
    assert!(endpoint(&config, "https://issuer.example/jwks#fragment", None).is_err());
}

#[tokio::test]
async fn runtime_caches_keys_and_throttles_unknown_kid_refresh() {
    let (key, keys) = jwt_material();
    let (idp, server, _certificate_directory, ca_path) = mock_idp(&keys).await;
    let mut config = config(OAuthMode::Jwt);
    config.issuer = idp.issuer.clone();
    config.ca_certificate = Some(ca_path);
    config.algorithms = Some(vec![OAuthAlgorithm::EdDsa]);
    config.max_concurrent_requests = Some(64);
    let runtime =
        OAuthRuntime::new_with_admission(config.clone(), Arc::new(OAuthAdmission::new(64)))
            .unwrap();
    let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);

    let valid = jwt_token(&key, "at+jwt", "alice", &config.issuer);
    runtime.validate(&valid, "alice", peer).await.unwrap();
    runtime.validate(&valid, "alice", peer).await.unwrap();
    assert_eq!(idp.metadata_requests.load(Ordering::SeqCst), 1);
    assert_eq!(idp.jwks_requests.load(Ordering::SeqCst), 1);

    let unknown = jwt_token_with_kid(&key, "at+jwt", "alice", &config.issuer, "unknown");
    assert!(matches!(
        runtime.validate(&unknown, "alice", peer).await,
        Err(Error::KeyUnavailable)
    ));
    assert!(matches!(
        runtime.validate(&unknown, "alice", peer).await,
        Err(Error::KeyUnavailable)
    ));
    assert_eq!(idp.jwks_requests.load(Ordering::SeqCst), 2);

    let (other_key, _) = jwt_material();
    let invalid_signature = jwt_token(&other_key, "at+jwt", "alice", &config.issuer);
    assert!(matches!(
        runtime.validate(&invalid_signature, "alice", peer).await,
        Err(Error::InvalidSignature)
    ));
    assert_eq!(idp.jwks_requests.load(Ordering::SeqCst), 2);
    server.abort();
}

#[tokio::test]
async fn runtime_bounds_provider_deadline_and_body() {
    let (key, keys) = jwt_material();
    let (idp, server, _certificate_directory, ca_path) = mock_idp(&keys).await;
    let mut config = config(OAuthMode::Jwt);
    config.issuer = idp.issuer.clone();
    config.ca_certificate = Some(ca_path);
    config.algorithms = Some(vec![OAuthAlgorithm::EdDsa]);
    config.http_timeout = Some(20);
    config.max_concurrent_requests = Some(64);
    let token = jwt_token(&key, "at+jwt", "alice", &config.issuer);
    let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);

    idp.slow_metadata.store(true, Ordering::SeqCst);
    let runtime =
        OAuthRuntime::new_with_admission(config.clone(), Arc::new(OAuthAdmission::new(64)))
            .unwrap();
    assert!(matches!(
        runtime.validate(&token, "alice", peer).await,
        Err(Error::Timeout)
    ));

    idp.slow_metadata.store(false, Ordering::SeqCst);
    idp.oversized_metadata.store(true, Ordering::SeqCst);
    let runtime =
        OAuthRuntime::new_with_admission(config, Arc::new(OAuthAdmission::new(64))).unwrap();
    assert!(matches!(
        runtime.validate(&token, "alice", peer).await,
        Err(Error::ResponseTooLarge)
    ));
    server.abort();
}

#[tokio::test]
async fn runtime_introspection_uses_basic_auth_without_result_cache() {
    let (_, keys) = jwt_material();
    let (idp, server, _certificate_directory, ca_path) = mock_idp(&keys).await;
    let directory = tempfile::TempDir::new().unwrap();
    let secret = directory.path().join("oauth.secret");
    std::fs::write(&secret, "super-secret-value\n").unwrap();
    let mut config = config(OAuthMode::Introspection);
    config.issuer = idp.issuer.clone();
    config.ca_certificate = Some(ca_path);
    config.client_id = Some("pgdog".into());
    config.client_secret_file = Some(secret);
    config.max_concurrent_requests = Some(64);
    let runtime =
        OAuthRuntime::new_with_admission(config, Arc::new(OAuthAdmission::new(64))).unwrap();
    let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);

    runtime.validate("opaque", "alice", peer).await.unwrap();
    runtime.validate("opaque", "alice", peer).await.unwrap();

    assert_eq!(idp.metadata_requests.load(Ordering::SeqCst), 1);
    assert_eq!(idp.introspection_requests.load(Ordering::SeqCst), 2);
    assert!(!idp.bad_basic_auth.load(Ordering::SeqCst));
    let debug = format!("{runtime:?}");
    assert!(!debug.contains("super-secret-value"));
    assert!(debug.contains("redacted"));
    server.abort();
}

#[tokio::test(start_paused = true)]
async fn cached_value_expires_without_stale_fallback() {
    let now = tokio::time::Instant::now();
    let cached = Cached::new("value", Duration::from_secs(5), now);
    assert_eq!(cached.get(now), Some(&"value"));

    tokio::time::advance(Duration::from_secs(5)).await;
    assert_eq!(cached.get(tokio::time::Instant::now()), None);
}
