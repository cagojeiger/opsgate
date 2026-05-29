use std::io;

use opsgate_core::Config;
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing_subscriber::EnvFilter;

mod auth;
mod error;
mod identity;
mod mcp;
mod me;
mod routes;
mod state;

use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load `.env` for local development; absence is fine in production.
    let _ = dotenvy::dotenv();
    init_tracing();

    let config = Config::load()?;

    // fail-fast: install the SIGTERM handler during boot so a failure here
    // aborts startup instead of leaving us without graceful shutdown.
    let signals = ShutdownSignals::install()?;

    let pool = opsgate_db::connect(&config).await?;
    opsgate_db::run_migrations(&pool).await?;
    info!(
        event = "db.ready",
        max_connections = config.db_max_connections
    );

    let bind_addr = config.bind_addr;
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let jwks_url = format!("{}/keys", config.authgate_url);
    let user_repo = opsgate_db::UserRepo::new(pool.clone());
    let resolver = opsgate_domain::Resolver::new(user_repo);
    let config = std::sync::Arc::new(config);
    let jwks = std::sync::Arc::new(auth::jwks::JwksCache::new(
        jwks_url,
        config.authgate_url.clone(),
        config.resource_url.clone(),
        config.jwks_cache_ttl,
        http.clone(),
    ));
    let state = AppState::new(
        pool.clone(),
        config.clone(),
        jwks,
        std::sync::Arc::new(resolver),
        http,
    );

    let listener = TcpListener::bind(bind_addr).await?;
    info!(event = "server.listening", addr = %bind_addr);

    let http_shutdown_token = CancellationToken::new();
    let http_shutdown = http_shutdown_token.clone().cancelled_owned();
    let server = async move {
        axum::serve(listener, routes::app(state))
            .with_graceful_shutdown(http_shutdown)
            .await
    };
    tokio::pin!(server);

    let server_result: Option<io::Result<()>> = tokio::select! {
        result = &mut server => Some(result),
        () = signals.wait() => None,
    };

    info!(event = "server.shutting_down");
    http_shutdown_token.cancel();

    let server_result = match server_result {
        Some(result) => result,
        None => server.await,
    };

    // Drain the connection pool before exiting so in-flight queries finish.
    pool.close().await;
    info!(event = "shutdown.complete");

    server_result.map_err(anyhow::Error::from)
}

struct ShutdownSignals {
    #[cfg(unix)]
    sigterm: tokio::signal::unix::Signal,
}

impl ShutdownSignals {
    fn install() -> io::Result<Self> {
        #[cfg(unix)]
        let sigterm = signal(SignalKind::terminate())?;

        Ok(Self {
            #[cfg(unix)]
            sigterm,
        })
    }

    async fn wait(mut self) {
        let ctrl_c = async {
            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::error!(%error, "failed to wait for Ctrl+C");
            }
        };

        #[cfg(unix)]
        let terminate = async {
            self.sigterm.recv().await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            () = ctrl_c => {}
            () = terminate => {}
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_error| {
        EnvFilter::new("opsgate_api=info,opsgate_db=info,tower_http=info")
    });

    let result = if std::env::var("LOG_FORMAT").as_deref() == Ok("json") {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .try_init()
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).try_init()
    };

    if let Err(error) = result {
        eprintln!("failed to initialize tracing: {error}");
    }
}
