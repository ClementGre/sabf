use axum::Json;
use axum::extract::ConnectInfo;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::SocketAddr;
use uuid::Uuid;

use crate::api::bytes::B64;
use crate::api::extractors::AuthUser;
use crate::error::{AppError, AppResult};
use crate::service::auth as auth_service;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub auth_key: B64,
    pub kdf_salt: B64,
    pub wrapped_umk: B64,
    pub public_key: B64,
    pub wrapped_privkey: B64,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub user_id: Uuid,
    pub username: String,
}

pub async fn register(
    State(state): State<AppState>,
    Json(body): Json<RegisterRequest>,
) -> AppResult<(StatusCode, Json<RegisterResponse>)> {
    let user = auth_service::register(
        state.pool(),
        &body.username,
        &body.auth_key.0,
        &body.kdf_salt.0,
        &body.wrapped_umk.0,
        &body.public_key.0,
        &body.wrapped_privkey.0,
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            user_id: user.id,
            username: user.username,
        }),
    ))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub auth_key: B64,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub kdf_salt: B64,
    pub kdf_params: Value,
    pub wrapped_umk: B64,
    pub wrapped_privkey: B64,
    pub public_key: B64,
}

pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<LoginRequest>,
) -> AppResult<Json<LoginResponse>> {
    let username_key = format!("user:{}", body.username);
    let ip_key = format!("ip:{}", addr.ip());
    if !state.login_rate_limiter().check(&username_key) || !state.login_rate_limiter().check(&ip_key) {
        return Err(AppError::TooManyRequests);
    }

    let result = auth_service::login(state.pool(), state.config(), &body.username, &body.auth_key.0).await?;
    Ok(Json(LoginResponse {
        access_token: result.access_token,
        refresh_token: result.refresh_token,
        kdf_salt: result.kdf_salt.into(),
        kdf_params: result.kdf_params,
        wrapped_umk: result.wrapped_umk.into(),
        wrapped_privkey: result.wrapped_privkey.into(),
        public_key: result.public_key.into(),
    }))
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
}

pub async fn refresh(
    State(state): State<AppState>,
    Json(body): Json<RefreshRequest>,
) -> AppResult<Json<RefreshResponse>> {
    let result = auth_service::refresh(state.pool(), state.config(), &body.refresh_token).await?;
    Ok(Json(RefreshResponse {
        access_token: result.access_token,
        refresh_token: result.refresh_token,
    }))
}

#[derive(Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

pub async fn logout(State(state): State<AppState>, Json(body): Json<LogoutRequest>) -> AppResult<StatusCode> {
    auth_service::logout(state.pool(), &body.refresh_token).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct ChangePassphraseRequest {
    pub current_auth_key: B64,
    pub new_auth_key: B64,
    pub new_kdf_salt: B64,
    pub new_wrapped_umk: B64,
}

pub async fn change_passphrase(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ChangePassphraseRequest>,
) -> AppResult<StatusCode> {
    auth_service::change_passphrase(
        state.pool(),
        auth.user_id,
        auth.session_id,
        &body.current_auth_key.0,
        &body.new_auth_key.0,
        &body.new_kdf_salt.0,
        &body.new_wrapped_umk.0,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
