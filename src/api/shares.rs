use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::bytes::B64;
use crate::api::extractors::AuthUser;
use crate::error::AppResult;
use crate::models::AppAccess;
use crate::repository::apps_access::PendingShare;
use crate::service::shares as shares_service;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct CreateShareRequest {
    pub recipient_user_id: Uuid,
    pub wrapped_dek: B64,
}

#[derive(Serialize)]
pub struct ShareResponse {
    pub app_id: Uuid,
    pub user_id: Uuid,
    pub role: String,
    pub status: String,
    pub wrapped_dek: B64,
    pub last_edit_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl From<AppAccess> for ShareResponse {
    fn from(a: AppAccess) -> Self {
        ShareResponse {
            app_id: a.app_id,
            user_id: a.user_id,
            role: a.role,
            status: a.status,
            wrapped_dek: a.wrapped_dek.into(),
            last_edit_at: a.last_edit_at,
            created_at: a.created_at,
        }
    }
}

pub async fn create(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(app_id): Path<Uuid>,
    Json(body): Json<CreateShareRequest>,
) -> AppResult<(StatusCode, Json<ShareResponse>)> {
    let access = shares_service::create_share(
        state.pool(),
        app_id,
        auth.user_id,
        body.recipient_user_id,
        &body.wrapped_dek.0,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(access.into())))
}

pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(app_id): Path<Uuid>,
) -> AppResult<Json<Vec<ShareResponse>>> {
    let shares = shares_service::list_shares(state.pool(), app_id, auth.user_id).await?;
    Ok(Json(shares.into_iter().map(ShareResponse::from).collect()))
}

#[derive(Serialize)]
pub struct PendingShareResponse {
    pub app_id: Uuid,
    pub slug: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

impl From<PendingShare> for PendingShareResponse {
    fn from(p: PendingShare) -> Self {
        PendingShareResponse {
            app_id: p.app_id,
            slug: p.slug,
            role: p.role,
            created_at: p.created_at,
        }
    }
}

pub async fn list_pending(
    State(state): State<AppState>,
    auth: AuthUser,
) -> AppResult<Json<Vec<PendingShareResponse>>> {
    let shares = shares_service::list_pending_for_user(state.pool(), auth.user_id).await?;
    Ok(Json(shares.into_iter().map(PendingShareResponse::from).collect()))
}

#[derive(Serialize)]
pub struct AcceptResponse {
    pub wrapped_dek: B64,
}

pub async fn accept(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(app_id): Path<Uuid>,
) -> AppResult<Json<AcceptResponse>> {
    let access = shares_service::accept(state.pool(), app_id, auth.user_id).await?;
    Ok(Json(AcceptResponse {
        wrapped_dek: access.wrapped_dek.into(),
    }))
}

pub async fn decline(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(app_id): Path<Uuid>,
) -> AppResult<StatusCode> {
    shares_service::decline(state.pool(), app_id, auth.user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn remove_member(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((app_id, user_id)): Path<(Uuid, Uuid)>,
) -> AppResult<StatusCode> {
    shares_service::remove_member(state.pool(), app_id, auth.user_id, user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
