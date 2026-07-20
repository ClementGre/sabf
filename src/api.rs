pub mod apps;
pub mod auth;
pub mod bytes;
pub mod data;
pub mod extractors;
pub mod shares;
pub mod users;

use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderName, Method};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::config::CorsOrigins;
use crate::state::AppState;

/// Default request-body cap. Covers auth, per-record app data, and everything
/// else; generous for JSON-wrapped ciphertext but small enough to blunt
/// memory-pressure abuse from authenticated clients.
const DEFAULT_BODY_LIMIT: usize = 1024 * 1024; // 1 MiB
/// Larger cap for app-level payloads that legitimately carry more: app
/// creation/metadata and, above all, DEK rotation (which re-uploads every
/// re-encrypted data row and access entry in a single request).
const LARGE_BODY_LIMIT: usize = 32 * 1024 * 1024; // 32 MiB

fn cors_layer(origins: &CorsOrigins) -> CorsLayer {
    let allow_origin = match origins {
        CorsOrigins::Any => AllowOrigin::any(),
        CorsOrigins::List(list) => AllowOrigin::list(
            list.iter()
                .filter_map(|o| o.parse().ok())
                .collect::<Vec<_>>(),
        ),
    };

    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([HeaderName::from_static("authorization"), HeaderName::from_static("content-type")])
}

pub fn router(state: AppState) -> Router {
    let cors = cors_layer(&state.config().cors_allowed_origins);

    Router::new()
        .route("/health", get(health))
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route("/auth/refresh", post(auth::refresh))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/change-passphrase", post(auth::change_passphrase))
        .route("/users/me", get(users::get_me).delete(users::delete_me))
        .route("/users/{username}", get(users::get_by_username))
        .route(
            "/apps",
            get(apps::list)
                .post(apps::create)
                .layer(DefaultBodyLimit::max(LARGE_BODY_LIMIT)),
        )
        .route(
            "/apps/{id}",
            get(apps::get)
                .patch(apps::patch)
                .delete(apps::delete)
                .layer(DefaultBodyLimit::max(LARGE_BODY_LIMIT)),
        )
        .route(
            "/apps/{id}/rotate",
            post(apps::rotate).layer(DefaultBodyLimit::max(LARGE_BODY_LIMIT)),
        )
        .route("/apps/{id}/leave", post(apps::leave))
        .route("/apps/{id}/data", get(data::list).post(data::create))
        .route(
            "/apps/{id}/data/{data_id}",
            axum::routing::patch(data::patch).delete(data::delete),
        )
        .route("/apps/{id}/shares", get(shares::list).post(shares::create))
        .route("/shares/pending", get(shares::list_pending))
        .route("/apps/{id}/shares/accept", post(shares::accept))
        .route("/apps/{id}/shares/decline", post(shares::decline))
        .route("/apps/{id}/shares/{user_id}", axum::routing::delete(shares::remove_member))
        .layer(DefaultBodyLimit::max(DEFAULT_BODY_LIMIT))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "healthy", "service": "sabf" }))
}
