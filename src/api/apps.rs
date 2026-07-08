use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::bytes::B64;
use crate::api::extractors::AuthUser;
use crate::error::AppResult;
use crate::models::AppWithAccess;
use crate::service::apps as apps_service;
use crate::state::AppState;

#[derive(Serialize)]
pub struct AppResponse {
    pub app_id: Uuid,
    pub slug: String,
    pub encrypted_metadata: B64,
    pub role: String,
    pub status: String,
    pub wrapped_dek: B64,
    pub last_edit_at: Option<DateTime<Utc>>,
}

impl From<AppWithAccess> for AppResponse {
    fn from(a: AppWithAccess) -> Self {
        AppResponse {
            app_id: a.app_id,
            slug: a.slug,
            encrypted_metadata: a.encrypted_metadata.into(),
            role: a.role,
            status: a.status,
            wrapped_dek: a.wrapped_dek.into(),
            last_edit_at: a.last_edit_at,
        }
    }
}

#[derive(Deserialize)]
pub struct ListQuery {
    pub slug: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<ListQuery>,
) -> AppResult<Json<Vec<AppResponse>>> {
    let apps = apps_service::list_apps(state.pool(), auth.user_id, query.slug.as_deref()).await?;
    Ok(Json(apps.into_iter().map(AppResponse::from).collect()))
}

#[derive(Deserialize)]
pub struct CreateAppRequest {
    pub app_id: Uuid,
    pub slug: String,
    pub encrypted_metadata: B64,
    pub wrapped_dek: B64,
}

pub async fn create(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateAppRequest>,
) -> AppResult<(StatusCode, Json<AppResponse>)> {
    let app = apps_service::create_app(
        state.pool(),
        auth.user_id,
        body.app_id,
        &body.slug,
        &body.encrypted_metadata.0,
        &body.wrapped_dek.0,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(app.into())))
}

pub async fn get(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(app_id): Path<Uuid>,
) -> AppResult<Json<AppResponse>> {
    let app = apps_service::get_app(state.pool(), app_id, auth.user_id).await?;
    Ok(Json(app.into()))
}

#[derive(Deserialize)]
pub struct PatchAppRequest {
    pub encrypted_metadata: B64,
}

pub async fn patch(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(app_id): Path<Uuid>,
    Json(body): Json<PatchAppRequest>,
) -> AppResult<StatusCode> {
    apps_service::patch_metadata(state.pool(), app_id, auth.user_id, &body.encrypted_metadata.0).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(app_id): Path<Uuid>,
) -> AppResult<StatusCode> {
    apps_service::delete_app(state.pool(), app_id, auth.user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn leave(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(app_id): Path<Uuid>,
) -> AppResult<StatusCode> {
    apps_service::leave_app(state.pool(), app_id, auth.user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct RotateDataItem {
    pub id: Uuid,
    pub new_encrypted_json: B64,
}

#[derive(Deserialize)]
pub struct RotateAccessItem {
    pub user_id: Uuid,
    pub new_wrapped_dek: B64,
}

#[derive(Deserialize)]
pub struct RotateRequest {
    pub new_encrypted_metadata: B64,
    pub data: Vec<RotateDataItem>,
    pub access: Vec<RotateAccessItem>,
}

pub async fn rotate(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(app_id): Path<Uuid>,
    Json(body): Json<RotateRequest>,
) -> AppResult<StatusCode> {
    let data = body
        .data
        .into_iter()
        .map(|d| apps_service::RotateDataItem {
            id: d.id,
            new_encrypted_json: d.new_encrypted_json.0,
        })
        .collect();
    let access = body
        .access
        .into_iter()
        .map(|a| apps_service::RotateAccessItem {
            user_id: a.user_id,
            new_wrapped_dek: a.new_wrapped_dek.0,
        })
        .collect();
    apps_service::rotate(
        state.pool(),
        app_id,
        auth.user_id,
        &body.new_encrypted_metadata.0,
        data,
        access,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
