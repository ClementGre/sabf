use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::bytes::B64;
use crate::api::extractors::AuthUser;
use crate::error::{AppError, AppResult};
use crate::models::AppData;
use crate::service::data as data_service;
use crate::state::AppState;

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 500;

#[derive(Serialize)]
pub struct DataResponse {
    pub id: Uuid,
    pub r#type: String,
    pub encrypted_json: B64,
    pub created_at: DateTime<Utc>,
    pub edited_at: DateTime<Utc>,
}

impl From<AppData> for DataResponse {
    fn from(d: AppData) -> Self {
        DataResponse {
            id: d.id,
            r#type: d.r#type,
            encrypted_json: d.encrypted_json.into(),
            created_at: d.created_at,
            edited_at: d.edited_at,
        }
    }
}

#[derive(Deserialize)]
pub struct CreateDataRequest {
    pub data_id: Uuid,
    pub r#type: String,
    pub encrypted_json: B64,
}

pub async fn create(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(app_id): Path<Uuid>,
    Json(body): Json<CreateDataRequest>,
) -> AppResult<(StatusCode, Json<DataResponse>)> {
    let row = data_service::create(
        state.pool(),
        app_id,
        auth.user_id,
        body.data_id,
        &body.r#type,
        &body.encrypted_json.0,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(row.into())))
}

#[derive(Deserialize)]
pub struct ListQuery {
    pub r#type: Option<String>,
    pub created_from: Option<DateTime<Utc>>,
    pub created_to: Option<DateTime<Utc>>,
    pub edited_from: Option<DateTime<Utc>>,
    pub edited_to: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct CursorPayload {
    created_at: DateTime<Utc>,
    id: Uuid,
}

fn decode_cursor(cursor: &str) -> AppResult<(DateTime<Utc>, Uuid)> {
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| AppError::BadRequest("invalid cursor".into()))?;
    let payload: CursorPayload =
        serde_json::from_slice(&bytes).map_err(|_| AppError::BadRequest("invalid cursor".into()))?;
    Ok((payload.created_at, payload.id))
}

fn encode_cursor(created_at: DateTime<Utc>, id: Uuid) -> String {
    let payload = CursorPayload { created_at, id };
    let bytes = serde_json::to_vec(&payload).expect("cursor payload always serializes");
    URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Serialize)]
pub struct ListResponse {
    pub data: Vec<DataResponse>,
    pub next_cursor: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(app_id): Path<Uuid>,
    Query(query): Query<ListQuery>,
) -> AppResult<Json<ListResponse>> {
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let cursor = query.cursor.as_deref().map(decode_cursor).transpose()?;

    let rows = data_service::list(
        state.pool(),
        app_id,
        auth.user_id,
        data_service::ListParams {
            r#type: query.r#type.as_deref(),
            created_from: query.created_from,
            created_to: query.created_to,
            edited_from: query.edited_from,
            edited_to: query.edited_to,
            cursor,
            limit,
        },
    )
    .await?;

    let next_cursor = if rows.len() as i64 == limit {
        rows.last().map(|r| encode_cursor(r.created_at, r.id))
    } else {
        None
    };

    Ok(Json(ListResponse {
        data: rows.into_iter().map(DataResponse::from).collect(),
        next_cursor,
    }))
}

#[derive(Deserialize)]
pub struct PatchDataRequest {
    pub encrypted_json: B64,
}

pub async fn patch(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((app_id, data_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<PatchDataRequest>,
) -> AppResult<Json<DataResponse>> {
    let row = data_service::patch(state.pool(), app_id, auth.user_id, data_id, &body.encrypted_json.0).await?;
    Ok(Json(row.into()))
}

pub async fn delete(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((app_id, data_id)): Path<(Uuid, Uuid)>,
) -> AppResult<StatusCode> {
    data_service::delete(state.pool(), app_id, auth.user_id, data_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
