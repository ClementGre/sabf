use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::api::bytes::B64;
use crate::api::extractors::AuthUser;
use crate::error::AppResult;
use crate::service::users as users_service;
use crate::state::AppState;

#[derive(Serialize)]
pub struct MeResponse {
    pub user_id: Uuid,
    pub username: String,
    pub public_key: B64,
    pub created_at: DateTime<Utc>,
}

pub async fn get_me(State(state): State<AppState>, auth: AuthUser) -> AppResult<Json<MeResponse>> {
    let user = users_service::get_me(state.pool(), auth.user_id).await?;
    Ok(Json(MeResponse {
        user_id: user.id,
        username: user.username,
        public_key: user.public_key.into(),
        created_at: user.created_at,
    }))
}

#[derive(Serialize)]
pub struct PublicUserResponse {
    pub user_id: Uuid,
    pub public_key: B64,
    pub kdf_salt: B64,
    pub kdf_params: Value,
}

pub async fn get_by_username(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> AppResult<Json<PublicUserResponse>> {
    let user = users_service::get_by_username(state.pool(), &username).await?;
    Ok(Json(PublicUserResponse {
        user_id: user.id,
        public_key: user.public_key.into(),
        kdf_salt: user.kdf_salt.into(),
        kdf_params: user.kdf_params,
    }))
}

#[derive(Deserialize)]
pub struct DeleteMeRequest {
    pub current_auth_key: B64,
}

pub async fn delete_me(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<DeleteMeRequest>,
) -> AppResult<StatusCode> {
    users_service::delete_me(state.pool(), auth.user_id, &body.current_auth_key.0).await?;
    Ok(StatusCode::NO_CONTENT)
}
