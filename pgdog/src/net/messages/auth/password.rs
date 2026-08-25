//! Password messages.

use std::fmt;
use std::str;

use bytes::BytesMut;

use super::super::code;
use super::super::prelude::*;

/// The decoded payload of a PostgreSQL `SASLInitialResponse`.
#[derive(Debug, PartialEq, Eq)]
pub struct SaslInitialResponse<'a> {
    pub name: &'a str,
    pub response: Option<&'a [u8]>,
}

/// An exact PostgreSQL PasswordMessage payload.
#[derive(Clone, PartialEq, Eq)]
pub struct Password {
    payload: Bytes,
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Password").field("redacted", &true).finish()
    }
}

impl Password {
    /// Create a SCRAM-SHA-256 initial response.
    pub fn sasl_initial(response: &str) -> Self {
        Self::sasl_initial_with("SCRAM-SHA-256", Some(response.as_bytes()))
    }

    /// Create a SASL initial response while preserving absent and empty responses.
    pub fn sasl_initial_with(name: &str, response: Option<&[u8]>) -> Self {
        let response_len = response.map_or(-1, |response| response.len() as i32);
        let mut payload = BytesMut::with_capacity(
            name.len() + 1 + size_of::<i32>() + response.map_or(0, <[u8]>::len),
        );
        payload.put_slice(name.as_bytes());
        payload.put_u8(0);
        payload.put_i32(response_len);
        if let Some(response) = response {
            payload.put_slice(response);
        }

        Self {
            payload: payload.freeze(),
        }
    }

    /// Create a raw SASL response.
    pub fn sasl_response(response: impl AsRef<[u8]>) -> Self {
        Self {
            payload: Bytes::copy_from_slice(response.as_ref()),
        }
    }

    /// Create a null-terminated password message.
    pub fn new_password(response: impl AsRef<str>) -> Self {
        let response = response.as_ref();
        let mut payload = BytesMut::with_capacity(response.len() + 1);
        payload.put_slice(response.as_bytes());
        payload.put_u8(0);
        Self {
            payload: payload.freeze(),
        }
    }

    /// Parse this payload as a null-terminated password.
    pub fn parse_password(&self) -> Result<&str, Error> {
        let Some(password) = self.payload.strip_suffix(b"\0") else {
            return Err(Error::UnexpectedPayload);
        };
        if password.contains(&0) {
            return Err(Error::UnexpectedPayload);
        }
        Ok(str::from_utf8(password)?)
    }

    /// Return a password when this is a valid null-terminated password message.
    pub fn password(&self) -> Option<&str> {
        self.parse_password().ok()
    }

    /// Parse this payload as a SASL initial response.
    pub fn sasl_initial_response(&self) -> Result<SaslInitialResponse<'_>, Error> {
        let Some(name_end) = self.payload.iter().position(|byte| *byte == 0) else {
            return Err(Error::UnexpectedPayload);
        };
        let name = str::from_utf8(&self.payload[..name_end])?;
        if name.is_empty() {
            return Err(Error::UnexpectedPayload);
        }

        let length_start = name_end + 1;
        let length_end = length_start + size_of::<i32>();
        let length = self
            .payload
            .get(length_start..length_end)
            .ok_or(Error::UnexpectedPayload)?;
        let length = i32::from_be_bytes(length.try_into()?);
        let response = self
            .payload
            .get(length_end..)
            .ok_or(Error::UnexpectedPayload)?;

        let response = match length {
            -1 if response.is_empty() => None,
            length if length >= 0 && length as usize == response.len() => Some(response),
            _ => return Err(Error::UnexpectedPayload),
        };

        Ok(SaslInitialResponse { name, response })
    }

    /// Parse this payload as a UTF-8 SASL response.
    pub fn parse_sasl_response(&self) -> Result<&str, Error> {
        Ok(str::from_utf8(&self.payload)?)
    }

    /// Return the exact message payload for binary-aware authentication mechanisms.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl FromBytes for Password {
    fn from_bytes(mut bytes: Bytes) -> Result<Self, Error> {
        if bytes.len() < 5 {
            return Err(Error::UnexpectedPayload);
        }
        code!(bytes, 'p');
        let len = bytes.get_i32();
        if len < 4 {
            return Err(Error::MalformedMessageLength(len));
        }
        if len as usize != bytes.remaining() + size_of::<i32>() {
            return Err(Error::UnexpectedPayload);
        }

        Ok(Self { payload: bytes })
    }
}

impl ToBytes for Password {
    fn to_bytes(&self) -> Bytes {
        let mut payload = Payload::named(self.code());
        payload.put(self.payload.clone());
        payload.freeze()
    }
}

impl Protocol for Password {
    fn code(&self) -> char {
        'p'
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_absent_and_empty_sasl_initial_responses() {
        for (response, expected) in [(None, None), (Some(&[][..]), Some(&[][..]))] {
            let message = Password::sasl_initial_with("OAUTHBEARER", response);
            let bytes = message.to_bytes();
            let parsed = Password::from_bytes(bytes).unwrap();
            let initial = parsed.sasl_initial_response().unwrap();

            assert_eq!(initial.name, "OAUTHBEARER");
            assert_eq!(initial.response, expected);
        }
    }

    #[test]
    fn parses_password_and_sasl_response_at_their_active_boundaries() {
        let password = Password::from_bytes(Password::new_password("secret").to_bytes()).unwrap();
        assert_eq!(password.parse_password().unwrap(), "secret");

        let response =
            Password::from_bytes(Password::sasl_response("proof-without-nul").to_bytes()).unwrap();
        assert_eq!(response.parse_sasl_response().unwrap(), "proof-without-nul");
    }

    #[test]
    fn rejects_malformed_envelopes_and_active_payloads() {
        let malformed = [
            Bytes::from_static(b"p\0\0\0\x03"),
            Bytes::from_static(b"p\0\0\0\x08abc"),
            Bytes::from_static(b"p\0\0\0\x05ab"),
        ];
        for bytes in malformed {
            assert!(Password::from_bytes(bytes).is_err());
        }

        let no_terminator = Password::from_bytes(Bytes::from_static(b"p\0\0\0\x0asecret")).unwrap();
        assert!(no_terminator.parse_password().is_err());

        let embedded_nul = Password::from_bytes(Bytes::from_static(b"p\0\0\0\x08a\0b\0")).unwrap();
        assert!(embedded_nul.parse_password().is_err());

        let invalid_mechanism =
            Password::from_bytes(Bytes::from_static(b"p\0\0\0\x0a\xff\0\xff\xff\xff\xff")).unwrap();
        assert!(invalid_mechanism.sasl_initial_response().is_err());
    }

    #[test]
    fn password_debug_is_redacted() {
        let password = Password::new_password("sentinel-token");
        let debug = format!("{password:?}");
        let raw = crate::net::messages::Message::new(password.to_bytes()).frontend();
        let raw_debug = format!("{raw:?}");

        assert!(!debug.contains("sentinel-token"));
        assert!(debug.contains("redacted"));
        assert!(!raw_debug.contains("sentinel-token"));
        assert!(raw_debug.contains("redacted"));
    }
}
