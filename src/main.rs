mod api;
mod config;
mod crypto;
mod error;
mod models;
mod repository;
mod service;
mod state;

use std::net::SocketAddr;

use sqlx::postgres::PgPoolOptions;

use config::Config;
use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("sabf=info".parse()?))
        .init();

    let config = Config::from_env();

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let state = AppState::new(pool, config);
    let app = api::router(state);

    tracing::info!(%addr, "starting sabf");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
