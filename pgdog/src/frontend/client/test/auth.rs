//! Client authentication tests.

use pgdog_config::{
    AuthType, OAuth, OAuthAlgorithm, OAuthMode, PassthroughAuth, users::PasswordKind,
};
use tokio::net::{TcpListener, TcpStream};

use crate::{
    auth::{
        AuthResult,
        oauth::{
            OAuthRuntime,
            test::{jwt_material, jwt_token, mock_idp},
        },
    },
    config::{config, set},
    expect_message,
    frontend::Client,
    net::{Authentication, ErrorResponse, Parameters, Password, Stream},
};

use super::{
    SpawnedClient,
    test_client::{read_message, send_message},
};

fn oauth_runtime() -> OAuthRuntime {
    OAuthRuntime::new(OAuth {
        mode: OAuthMode::Jwt,
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
    })
    .unwrap()
}

/// Connect to the admin database and answer the plaintext password
/// request with the given password.
async fn login_admin(password: &str) -> SpawnedClient {
    let cfg = config();
    let mut params = Parameters::default();
    params.insert("user", cfg.config.admin.user.as_str());
    params.insert("database", cfg.config.admin.name.as_str());

    let mut client = SpawnedClient::new_with_login(params).await;

    // Both the admin and the passthrough branches request the password
    // in plaintext; what matters is what happens with the answer.
    let request = expect_message!(client.read().await, Authentication);
    assert!(matches!(request, Authentication::ClearTextPassword));

    client.send(Password::new_password(password)).await;
    client
}

/// Admin connections must be authenticated against the admin password even
/// when passthrough auth is enabled. Regression test for the passthrough
/// branch running first and accepting any password for the admin database.
#[tokio::test]
async fn test_oauth_password_branch_fails_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::spawn(TcpStream::connect(addr));
    let (server, _) = listener.accept().await.unwrap();
    let _client = client.await.unwrap().unwrap();
    let mut stream = Stream::plain(server, 4096);

    let result = Client::check_password(
        &mut stream,
        "alice",
        &AuthType::OAuth,
        &[PasswordKind::Plain("ignored".into())],
    )
    .await
    .unwrap();

    assert_eq!(result, AuthResult::NoPasswordMatch);
}

#[tokio::test]
async fn test_oauth_discovery_is_terminal() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let runtime = oauth_runtime();
    let server = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let mut stream = Stream::plain(stream, 4096);
        Client::check_oauth(&mut stream, "alice", peer.ip(), &runtime)
            .await
            .unwrap()
    });
    let mut client = TcpStream::connect(addr).await.unwrap();

    let request = expect_message!(read_message(&mut client).await, Authentication);
    assert!(matches!(request, Authentication::Sasl(name) if name == "OAUTHBEARER"));
    send_message(
        &mut client,
        Password::sasl_initial_with("OAUTHBEARER", None),
    )
    .await;
    let challenge = expect_message!(read_message(&mut client).await, Authentication);
    assert!(matches!(challenge, Authentication::SaslContinue(_)));
    send_message(&mut client, Password::sasl_response([0x01])).await;
    let error = ErrorResponse::try_from(read_message(&mut client).await).unwrap();

    assert_eq!(error.code, "28000");
    assert_eq!(error.message, "OAuth authentication failed");
    assert!(!server.await.unwrap());
}

#[tokio::test]
async fn test_oauth_token_reaches_validator() {
    let (key, keys) = jwt_material();
    let (idp, idp_server, _certificate_directory, ca_path) = mock_idp(&keys).await;
    let mut oauth = oauth_runtime().config().clone();
    oauth.issuer = idp.issuer.clone();
    oauth.ca_certificate = Some(ca_path);
    oauth.algorithms = Some(vec![OAuthAlgorithm::EdDsa]);
    let runtime = OAuthRuntime::new(oauth).unwrap();
    let token = jwt_token(&key, "at+jwt", "alice", &idp.issuer);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let mut stream = Stream::plain(stream, 4096);
        Client::check_oauth(&mut stream, "alice", peer.ip(), &runtime)
            .await
            .unwrap()
    });
    let mut client = TcpStream::connect(addr).await.unwrap();

    let request = expect_message!(read_message(&mut client).await, Authentication);
    assert!(matches!(request, Authentication::Sasl(name) if name == "OAUTHBEARER"));
    let response = format!("n,,\x01auth=Bearer {token}\x01\x01");
    send_message(
        &mut client,
        Password::sasl_initial_with("OAUTHBEARER", Some(response.as_bytes())),
    )
    .await;

    assert!(server.await.unwrap());
    idp_server.abort();
}

#[tokio::test]
async fn test_oauth_prevalidation_rejection_skips_provider() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let runtime = oauth_runtime();
    let server = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let mut stream = Stream::plain(stream, 4096);
        Client::reject_oauth(&mut stream, peer.ip(), &runtime)
            .await
            .unwrap();
    });
    let mut client = TcpStream::connect(addr).await.unwrap();

    let request = expect_message!(read_message(&mut client).await, Authentication);
    assert!(matches!(request, Authentication::Sasl(name) if name == "OAUTHBEARER"));
    send_message(
        &mut client,
        Password::sasl_initial_with(
            "OAUTHBEARER",
            Some(b"n,,\x01auth=Bearer valid-shaped-token\x01\x01"),
        ),
    )
    .await;
    let challenge = expect_message!(read_message(&mut client).await, Authentication);
    assert!(matches!(challenge, Authentication::SaslContinue(_)));
    send_message(&mut client, Password::sasl_response([0x01])).await;
    let error = ErrorResponse::try_from(read_message(&mut client).await).unwrap();

    assert_eq!(error.message, "OAuth authentication failed");
    server.await.unwrap();
}

#[tokio::test]
async fn test_admin_password_checked_with_passthrough_auth() {
    crate::logger();
    crate::config::load_test();

    let mut cfg = (*config()).clone();
    cfg.config.general.auth_type = AuthType::Plain;
    cfg.config.general.passthrough_auth = PassthroughAuth::EnabledPlain;
    cfg.config.admin.password = "admin-password".into();
    set(cfg).unwrap();

    // The wrong password is rejected instead of being passed through.
    let mut client = login_admin("not-the-admin-password").await;
    let error = ErrorResponse::try_from(client.read().await).unwrap();
    assert_eq!(error.code, "28000");
    client.join().await;

    // The correct password is accepted.
    let mut client = login_admin("admin-password").await;
    let response = expect_message!(client.read().await, Authentication);
    assert!(matches!(response, Authentication::Ok));
    client.read_until('Z').await;
    client.join().await;
}
