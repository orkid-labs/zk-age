//! zk-age backend — privacy-preserving age verification with ZK proofs.
//!
//! Architecture:
//! - `POST /api/issue` — issuer signs a birthdate commitment (simulated ID authority)
//! - `POST /api/prove` — user generates a Groth16 proof locally (via snarkjs subprocess)
//! - `POST /api/verify` — proof is submitted to zkVerify (via Kurier REST API) for on-chain verification
//! - `GET /api/health` — health check
//! - `GET /api/stats` — proof count, verification count, metrics for Thrive milestones
//!
//! The frontend never touches blockchain. Users just click "I'm 18+" and get
//! a verified result. The Rust backend orchestrates the ZK workflow.

pub mod attestation_energy;
pub mod auth;
pub mod issuer;
pub mod prover;
pub mod zkverify;
pub mod routes;
pub mod state;
pub mod types;

use std::sync::Arc;
use axum::http::HeaderValue;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::EnvFilter;

/// Build a CORS layer restricted to origins listed in `ORKID_CORS_ORIGINS`
/// (comma-separated). Falls back to `http://localhost:3000` in dev mode when
/// the variable is unset.
fn get_cors_layer() -> CorsLayer {
    let origins: Vec<String> = std::env::var("ORKID_CORS_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:3000".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any);

    if origins.len() == 1 {
        let origin: HeaderValue = origins[0]
            .parse()
            .expect("invalid CORS origin in ORKID_CORS_ORIGINS");
        cors.allow_origin(origin)
    } else {
        let parsed: Vec<HeaderValue> = origins
            .iter()
            .map(|s| s.parse().expect("invalid CORS origin in ORKID_CORS_ORIGINS"))
            .collect();
        cors.allow_origin(parsed)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let state = Arc::new(state::AppState::new());
    let cors = get_cors_layer();
    let app = routes::router(state.clone()).layer(cors);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let addr = format!("0.0.0.0:{}", port);
    tracing::info!("zk-age backend listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
