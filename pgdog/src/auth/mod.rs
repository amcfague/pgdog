//! PostgreSQL authentication mechanisms.

pub mod auth_result;
pub mod error;
pub mod md5;
// U4 wires the completed OAuth runtime into frontend login.
#[allow(dead_code)]
pub mod oauth;
pub mod scram;
pub mod vault;

pub use auth_result::AuthResult;
pub use error::Error;
