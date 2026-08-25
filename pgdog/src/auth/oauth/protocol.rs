use std::str;

use pgdog_config::OAuth;
use serde::Serialize;
use thiserror::Error;

use crate::net::{Authentication, ErrorResponse, FromBytes, Password, Protocol, Stream, ToBytes};

pub const MAX_OAUTH_PASSWORD_FRAME_LEN: usize = 128 * 1024;
pub const MAX_BEARER_TOKEN_LEN: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid OAUTHBEARER GS2 header")]
    InvalidGs2Header,
    #[error("OAUTHBEARER authorization identity is not supported")]
    AuthorizationIdentity,
    #[error("invalid OAUTHBEARER attribute")]
    InvalidAttribute,
    #[error("duplicate OAUTHBEARER {0} attribute")]
    DuplicateAttribute(&'static str),
    #[error("unknown OAUTHBEARER attribute")]
    UnknownAttribute,
    #[error("invalid OAUTHBEARER authentication scheme")]
    InvalidScheme,
    #[error("invalid OAUTHBEARER token")]
    InvalidToken,
    #[error("OAUTHBEARER token exceeds the configured limit")]
    TokenTooLarge,
    #[error("OAUTHBEARER response is not UTF-8")]
    InvalidUtf8,
    #[error("invalid OAUTHBEARER acknowledgement")]
    InvalidAcknowledgement,
    #[error("OAuth configuration error: {0}")]
    Config(#[from] pgdog_config::Error),
    #[error("OAuth network error: {0}")]
    Network(#[from] crate::net::Error),
    #[error("OAuth challenge serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, PartialEq, Eq)]
pub enum InitialResponse<'a> {
    Discovery,
    Bearer(BearerResponse<'a>),
}

#[derive(Debug, PartialEq, Eq)]
pub struct BearerResponse<'a> {
    pub token: &'a str,
    pub host: Option<&'a str>,
    pub port: Option<u16>,
}

pub fn parse_initial_response(response: Option<&[u8]>) -> Result<InitialResponse<'_>, Error> {
    let Some(response) = response else {
        return Ok(InitialResponse::Discovery);
    };
    if response.is_empty() {
        return Ok(InitialResponse::Discovery);
    }
    if response.contains(&0) {
        return Err(Error::InvalidAttribute);
    }

    let response = str::from_utf8(response).map_err(|_| Error::InvalidUtf8)?;
    let Some(attributes) = response.strip_prefix("n,,") else {
        return Err(if response.starts_with("n,") {
            Error::AuthorizationIdentity
        } else {
            Error::InvalidGs2Header
        });
    };
    if attributes.len() <= 2 || !attributes.starts_with('\x01') || !attributes.ends_with("\x01\x01")
    {
        return Err(Error::InvalidAttribute);
    }

    let attributes = &attributes[1..attributes.len() - 2];
    let mut token = None;
    let mut host = None;
    let mut port = None;

    for attribute in attributes.split('\x01') {
        let Some((name, value)) = attribute.split_once('=') else {
            return Err(Error::InvalidAttribute);
        };
        if value.is_empty() {
            return Err(Error::InvalidAttribute);
        }

        match name {
            "auth" => {
                if token.is_some() {
                    return Err(Error::DuplicateAttribute("auth"));
                }
                let Some(value) = value.strip_prefix("Bearer ") else {
                    return Err(Error::InvalidScheme);
                };
                if value.len() > MAX_BEARER_TOKEN_LEN {
                    return Err(Error::TokenTooLarge);
                }
                if !valid_bearer_token(value) {
                    return Err(Error::InvalidToken);
                }
                token = Some(value);
            }
            "host" => {
                if host.replace(value).is_some() {
                    return Err(Error::DuplicateAttribute("host"));
                }
            }
            "port" => {
                if port.is_some() {
                    return Err(Error::DuplicateAttribute("port"));
                }
                let value = value.parse().map_err(|_| Error::InvalidAttribute)?;
                if value == 0 {
                    return Err(Error::InvalidAttribute);
                }
                port = Some(value);
            }
            _ => return Err(Error::UnknownAttribute),
        }
    }

    Ok(InitialResponse::Bearer(BearerResponse {
        token: token.ok_or(Error::InvalidAttribute)?,
        host,
        port,
    }))
}

fn valid_bearer_token(token: &str) -> bool {
    let mut saw_data = false;
    let mut saw_padding = false;
    for byte in token.bytes() {
        if byte == b'=' {
            saw_padding = true;
        } else if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        {
            if saw_padding {
                return false;
            }
            saw_data = true;
        } else {
            return false;
        }
    }
    saw_data
}

#[derive(Serialize)]
struct Challenge<'a> {
    status: &'static str,
    #[serde(rename = "openid-configuration")]
    openid_configuration: &'a str,
    scope: String,
}

pub fn discovery_challenge(config: &OAuth) -> Result<Authentication, Error> {
    let discovery_url = config.discovery_url()?;
    let challenge = Challenge {
        status: "invalid_token",
        openid_configuration: discovery_url.as_str(),
        scope: config.scopes.join(" "),
    };
    Ok(Authentication::SaslContinue(serde_json::to_string(
        &challenge,
    )?))
}

pub fn acknowledge(response: &[u8]) -> Result<(), Error> {
    if response == [0x01] {
        Ok(())
    } else {
        Err(Error::InvalidAcknowledgement)
    }
}

pub async fn send_failure(stream: &mut Stream, config: &OAuth) -> Result<(), Error> {
    stream.send_flush(&discovery_challenge(config)?).await?;
    let message = stream.read_bounded(MAX_OAUTH_PASSWORD_FRAME_LEN).await?;
    if message.code() != 'p' {
        return Err(crate::net::Error::UnexpectedMessage('p', message.code()).into());
    }
    let password = Password::from_bytes(message.to_bytes())?;
    acknowledge(password.payload())?;
    stream.fatal(ErrorResponse::oauth()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use bytes::{BufMut, Bytes, BytesMut};
    use pgdog_config::{OAuth, OAuthMode};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    async fn read_message(stream: &mut TcpStream) -> Bytes {
        let code = stream.read_u8().await.unwrap();
        let len = stream.read_i32().await.unwrap();
        let mut body = vec![0; len as usize - 4];
        stream.read_exact(&mut body).await.unwrap();
        let mut message = BytesMut::with_capacity(len as usize + 1);
        message.put_u8(code);
        message.put_i32(len);
        message.put_slice(&body);
        message.freeze()
    }

    fn config() -> OAuth {
        OAuth {
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
        }
    }

    #[test]
    fn parses_discovery_and_bearer_responses() {
        assert_eq!(
            parse_initial_response(None).unwrap(),
            InitialResponse::Discovery
        );
        assert_eq!(
            parse_initial_response(Some(&[])).unwrap(),
            InitialResponse::Discovery
        );

        let parsed = parse_initial_response(Some(
            b"n,,\x01host=db.example\x01port=6432\x01auth=Bearer abc.DEF-123_~+/=\x01\x01",
        ))
        .unwrap();
        assert_eq!(
            parsed,
            InitialResponse::Bearer(BearerResponse {
                token: "abc.DEF-123_~+/=",
                host: Some("db.example"),
                port: Some(6432),
            })
        );
    }

    #[test]
    fn rejects_malformed_bearer_responses() {
        let invalid: &[&[u8]] = &[
            b"y,,\x01auth=Bearer token\x01\x01",
            b"n,a=user,\x01auth=Bearer token\x01\x01",
            b"n,,auth=Bearer token\x01\x01",
            b"n,,\x01\x01",
            b"n,,\x01auth=Basic token\x01\x01",
            b"n,,\x01auth=Bearer \x01\x01",
            b"n,,\x01auth=Bearer token\x01auth=Bearer other\x01\x01",
            b"n,,\x01auth=Bearer token\x01host=a\x01host=b\x01\x01",
            b"n,,\x01auth=Bearer token\x01port=0\x01\x01",
            b"n,,\x01auth=Bearer token\x01unknown=x\x01\x01",
            b"n,,\x01auth=Bearer token\x01",
            b"n,,\x01auth=Bearer token\x01\x01trailing",
            b"n,,\x01auth=Bearer to ken\x01\x01",
            b"n,,\x01auth=Bearer token\0\x01\x01",
            b"n,,\x01auth=Bearer \xff\x01\x01",
        ];

        for response in invalid {
            assert!(
                parse_initial_response(Some(response)).is_err(),
                "{response:?}"
            );
        }
    }

    #[test]
    fn rejects_oversized_bearer_token() {
        let response = format!(
            "n,,\x01auth=Bearer {}\x01\x01",
            "a".repeat(MAX_BEARER_TOKEN_LEN + 1)
        );
        assert!(matches!(
            parse_initial_response(Some(response.as_bytes())),
            Err(Error::TokenTooLarge)
        ));
    }

    #[test]
    fn discovery_json_has_only_public_fields() {
        let challenge = discovery_challenge(&config()).unwrap();
        let Authentication::SaslContinue(json) = challenge else {
            panic!("expected SASL continue")
        };
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "openid-configuration".to_string(),
                "scope".to_string(),
                "status".to_string(),
            ])
        );
        assert_eq!(value["status"], "invalid_token");
        assert_eq!(
            value["openid-configuration"],
            "https://issuer.example/tenant/.well-known/openid-configuration"
        );
        assert_eq!(value["scope"], "openid db.connect");
    }

    #[test]
    fn acknowledgement_is_exactly_one_control_byte() {
        assert!(acknowledge(&[0x01]).is_ok());
        assert!(acknowledge(&[]).is_err());
        assert!(acknowledge(&[0x01, 0x01]).is_err());
        assert!(acknowledge(b"x").is_err());
    }

    #[test]
    fn error_debug_never_contains_input() {
        let error =
            parse_initial_response(Some(b"n,,\x01auth=Bearer sentinel-token\x01bad=x\x01\x01"))
                .unwrap_err();
        assert!(!format!("{error:?}").contains("sentinel-token"));
        assert!(!error.to_string().contains("sentinel-token"));
    }

    #[test]
    fn bearer_response_is_borrowed() {
        let bytes = Bytes::from_static(b"n,,\x01auth=Bearer token\x01\x01");
        let parsed = parse_initial_response(Some(&bytes)).unwrap();
        assert!(matches!(parsed, InitialResponse::Bearer(_)));
    }

    #[tokio::test]
    async fn failure_challenge_requires_ack_then_sends_generic_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = config();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = Stream::plain(stream, 4096);
            send_failure(&mut stream, &config).await.unwrap();
        });
        let mut client = TcpStream::connect(addr).await.unwrap();

        let challenge = Authentication::from_bytes(read_message(&mut client).await).unwrap();
        assert!(matches!(challenge, Authentication::SaslContinue(_)));
        client
            .write_all(&Password::sasl_response([0x01]).to_bytes())
            .await
            .unwrap();

        let error = ErrorResponse::from_bytes(read_message(&mut client).await).unwrap();
        assert_eq!(error.code, "28000");
        assert_eq!(error.message, "OAuth authentication failed");
        server.await.unwrap();
    }
}
