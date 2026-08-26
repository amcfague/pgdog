//! Atomically published configuration and connection state.

use std::fmt;
use std::sync::Arc;

use arc_swap::ArcSwap;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use thiserror::Error;
use tokio_rustls::TlsAcceptor;

use crate::auth::oauth::{Error as OAuthError, OAuthRuntime};
use crate::backend::databases::{Databases, from_config};
use crate::backend::{self, reload_notify};
use crate::config::{self, AuthType, ConfigAndUsers};
use crate::frontend::PreparedStatements;
use crate::frontend::router::parser::Cache;
use crate::net;

static LIVE: Lazy<ArcSwap<LiveState>> = Lazy::new(|| ArcSwap::from_pointee(LiveState::default()));
static COMMIT_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

#[derive(Debug, Error)]
pub enum Error {
    #[error("configuration preparation failed: {0}")]
    Config(#[from] config::Error),
    #[error("database preparation failed: {0}")]
    Backend(#[from] backend::Error),
    #[error("TLS preparation failed: {0}")]
    Tls(#[from] net::Error),
    #[error("OAuth preparation failed: {0}")]
    OAuth(#[from] OAuthError),
    #[error("OAuth configuration is missing")]
    MissingOAuth,
}

pub struct LiveState {
    pub config: Arc<ConfigAndUsers>,
    databases: Arc<DatabaseGeneration>,
    pub tls_acceptor: Option<Arc<TlsAcceptor>>,
    pub oauth: Option<Arc<OAuthRuntime>>,
}

impl fmt::Debug for LiveState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveState")
            .field("auth_type", &self.config.config.general.auth_type)
            .field("tls", &self.tls_acceptor.is_some())
            .field("oauth", &self.oauth.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for LiveState {
    fn default() -> Self {
        Self {
            config: Arc::new(ConfigAndUsers::default()),
            databases: Arc::new(DatabaseGeneration::default()),
            tls_acceptor: None,
            oauth: None,
        }
    }
}

impl LiveState {
    pub fn databases(&self) -> Arc<Databases> {
        Arc::clone(&self.databases.databases)
    }
}

#[derive(Default)]
struct DatabaseGeneration {
    databases: Arc<Databases>,
}

impl DatabaseGeneration {
    fn new(databases: Databases) -> Self {
        Self {
            databases: Arc::new(databases),
        }
    }
}

impl Drop for DatabaseGeneration {
    fn drop(&mut self) {
        self.databases.shutdown();
    }
}

pub struct PreparedLiveState {
    config: Arc<ConfigAndUsers>,
    databases: Databases,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
    oauth: Option<Arc<OAuthRuntime>>,
}

pub fn live() -> Arc<LiveState> {
    LIVE.load_full()
}

pub fn prepare_reload(candidate: ConfigAndUsers) -> Result<PreparedLiveState, Error> {
    let config = Arc::new(config::prepare(candidate)?);
    let oauth = if config.config.general.auth_type == AuthType::OAuth {
        Some(Arc::new(OAuthRuntime::new(
            config.config.oauth.clone().ok_or(Error::MissingOAuth)?,
        )?))
    } else {
        None
    };
    let databases = from_config(&config);
    let tls_acceptor = net::tls::prepare_acceptor(&config)?.map(Arc::new);

    Ok(PreparedLiveState {
        config,
        databases,
        tls_acceptor,
        oauth,
    })
}

pub fn commit_reload(
    prepared: PreparedLiveState,
    preserve_connections: bool,
) -> Result<Arc<LiveState>, Error> {
    let _commit = COMMIT_LOCK.lock();
    let _ready = reload_notify::started();
    let previous = live();

    if preserve_connections {
        previous
            .databases
            .databases
            .move_conns_to(&prepared.databases)?;
    }
    prepared.databases.launch();
    if let Some(oauth) = &prepared.oauth {
        oauth.activate_limit();
    }

    let state = Arc::new(LiveState {
        config: prepared.config,
        databases: Arc::new(DatabaseGeneration::new(prepared.databases)),
        tls_acceptor: prepared.tls_acceptor,
        oauth: prepared.oauth,
    });
    LIVE.store(Arc::clone(&state));

    PreparedStatements::global()
        .write()
        .close_unused(state.config.config.general.prepared_statements_limit);
    Cache::resize(state.config.config.general.query_cache_limit);

    Ok(state)
}

pub fn reload_config(
    config: ConfigAndUsers,
    preserve_connections: bool,
) -> Result<Arc<LiveState>, Error> {
    commit_reload(prepare_reload(config)?, preserve_connections)
}

/// Replace only the configuration snapshot. Test helpers use this before building pools.
#[cfg(test)]
pub fn set_config(config: ConfigAndUsers) -> Arc<LiveState> {
    let _commit = COMMIT_LOCK.lock();
    let previous = live();
    let state = Arc::new(LiveState {
        config: Arc::new(config),
        databases: Arc::clone(&previous.databases),
        tls_acceptor: previous.tls_acceptor.clone(),
        oauth: previous.oauth.clone(),
    });
    LIVE.store(Arc::clone(&state));
    state
}

#[cfg(test)]
pub fn replace_databases(
    databases: Databases,
    preserve_connections: bool,
) -> Result<Arc<LiveState>, Error> {
    let _commit = COMMIT_LOCK.lock();
    let _ready = reload_notify::started();
    let previous = live();
    if preserve_connections {
        previous.databases.databases.move_conns_to(&databases)?;
    }
    databases.launch();
    let state = Arc::new(LiveState {
        config: Arc::clone(&previous.config),
        databases: Arc::new(DatabaseGeneration::new(databases)),
        tls_acceptor: previous.tls_acceptor.clone(),
        oauth: previous.oauth.clone(),
    });
    LIVE.store(Arc::clone(&state));
    Ok(state)
}

pub fn replace_tls_acceptor(acceptor: Option<Arc<TlsAcceptor>>) -> Arc<LiveState> {
    let _commit = COMMIT_LOCK.lock();
    let previous = live();
    let state = Arc::new(LiveState {
        config: Arc::clone(&previous.config),
        databases: Arc::clone(&previous.databases),
        tls_acceptor: acceptor,
        oauth: previous.oauth.clone(),
    });
    LIVE.store(Arc::clone(&state));
    state
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use pgdog_config::{AuthType, Database, OAuth, OAuthMode, PoolerMode, User};

    use super::*;

    fn tls_file(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("tls")
            .join(name)
    }

    fn backend_config(pooler_mode: PoolerMode) -> ConfigAndUsers {
        let mut config = ConfigAndUsers::default();
        config.config.general.auth_type = AuthType::Trust;
        config.config.general.min_pool_size = 0;
        config.config.databases = vec![Database {
            name: "db".into(),
            host: "127.0.0.1".into(),
            port: 5432,
            ..Default::default()
        }];
        config.users.users = vec![User {
            name: "alice".into(),
            database: "db".into(),
            pooler_mode: Some(pooler_mode),
            ..Default::default()
        }];
        config
    }

    fn oauth_config() -> ConfigAndUsers {
        let mut config = ConfigAndUsers::default();
        config.config.general.auth_type = AuthType::OAuth;
        config.config.general.tls_client_required = true;
        config.config.general.tls_certificate = Some(tls_file("cert.pem"));
        config.config.general.tls_private_key = Some(tls_file("key.pem"));
        config.config.oauth = Some(OAuth {
            mode: OAuthMode::Jwt,
            issuer: "https://issuer.example".into(),
            audience: "postgres".into(),
            scopes: vec!["db.connect".into()],
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
        });
        config
    }

    #[test]
    fn commit_keeps_captured_generation_immutable() {
        set_config(ConfigAndUsers::default());
        let original = live();
        let mut config = (*original.config).clone();
        config.config.general.auth_type = AuthType::Trust;
        let prepared = prepare_reload(config).unwrap();
        let committed = commit_reload(prepared, false).unwrap();

        assert_eq!(original.config.config.general.auth_type, AuthType::Scram);
        assert_eq!(committed.config.config.general.auth_type, AuthType::Trust);
        assert_eq!(live().config.config.general.auth_type, AuthType::Trust);
    }

    #[test]
    fn connection_uses_the_captured_database_generation() {
        let captured = commit_reload(
            prepare_reload(backend_config(PoolerMode::Transaction)).unwrap(),
            false,
        )
        .unwrap();
        commit_reload(
            prepare_reload(backend_config(PoolerMode::Session)).unwrap(),
            false,
        )
        .unwrap();

        let captured_connection =
            crate::backend::pool::Connection::new_with_state("alice", "db", false, &captured)
                .unwrap();
        let current_connection =
            crate::backend::pool::Connection::new("alice", "db", false).unwrap();

        assert_eq!(
            captured_connection.cluster().unwrap().pooler_mode(),
            PoolerMode::Transaction,
        );
        assert_eq!(
            current_connection.cluster().unwrap().pooler_mode(),
            PoolerMode::Session,
        );
    }

    #[test]
    fn failed_preparation_does_not_publish_candidate() {
        let before = live();
        let mut config = oauth_config();
        config.config.general.tls_private_key = Some(PathBuf::from("missing-key.pem"));

        assert!(prepare_reload(config).is_err());
        assert!(Arc::ptr_eq(&before, &live()));
    }

    #[test]
    fn oauth_runtime_and_tls_publish_together() {
        let prepared = prepare_reload(oauth_config()).unwrap();
        let committed = commit_reload(prepared, false).unwrap();

        assert_eq!(committed.config.config.general.auth_type, AuthType::OAuth);
        assert!(committed.oauth.is_some());
        assert!(committed.tls_acceptor.is_some());
        assert!(Arc::ptr_eq(&committed.config, &crate::config::config()));
        assert!(Arc::ptr_eq(
            &committed.databases(),
            &crate::backend::databases::databases(),
        ));
        assert!(Arc::ptr_eq(
            committed.tls_acceptor.as_ref().unwrap(),
            &crate::net::tls::acceptor().unwrap(),
        ));
    }
}
