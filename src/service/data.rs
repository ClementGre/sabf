use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::AppData;
use crate::repository::{apps_access, apps_data};

async fn require_active_member(pool: &PgPool, app_id: Uuid, user_id: Uuid) -> AppResult<()> {
    let access = apps_access::find(pool, app_id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if access.status != "active" {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

pub async fn create(
    pool: &PgPool,
    app_id: Uuid,
    user_id: Uuid,
    data_id: Uuid,
    r#type: &str,
    encrypted_json: &[u8],
) -> AppResult<AppData> {
    require_active_member(pool, app_id, user_id).await?;

    let mut tx = pool.begin().await?;
    let row = apps_data::create(&mut *tx, data_id, app_id, r#type, encrypted_json).await?;
    apps_access::bump_last_edit(&mut tx, app_id, user_id).await?;
    tx.commit().await?;
    Ok(row)
}

pub struct ListParams<'a> {
    pub r#type: Option<&'a str>,
    pub created_from: Option<DateTime<Utc>>,
    pub created_to: Option<DateTime<Utc>>,
    pub edited_from: Option<DateTime<Utc>>,
    pub edited_to: Option<DateTime<Utc>>,
    pub cursor: Option<(DateTime<Utc>, Uuid)>,
    pub limit: i64,
}

pub async fn list(pool: &PgPool, app_id: Uuid, user_id: Uuid, params: ListParams<'_>) -> AppResult<Vec<AppData>> {
    require_active_member(pool, app_id, user_id).await?;

    let filters = apps_data::ListFilters {
        r#type: params.r#type,
        created_from: params.created_from,
        created_to: params.created_to,
        edited_from: params.edited_from,
        edited_to: params.edited_to,
        cursor: params.cursor,
        limit: params.limit,
    };
    Ok(apps_data::list(pool, app_id, &filters).await?)
}

pub async fn patch(
    pool: &PgPool,
    app_id: Uuid,
    user_id: Uuid,
    data_id: Uuid,
    encrypted_json: &[u8],
) -> AppResult<AppData> {
    require_active_member(pool, app_id, user_id).await?;

    let mut tx = pool.begin().await?;
    let row = apps_data::update(&mut *tx, app_id, data_id, encrypted_json)
        .await?
        .ok_or(AppError::NotFound)?;
    apps_access::bump_last_edit(&mut tx, app_id, user_id).await?;
    tx.commit().await?;
    Ok(row)
}

pub async fn delete(pool: &PgPool, app_id: Uuid, user_id: Uuid, data_id: Uuid) -> AppResult<()> {
    require_active_member(pool, app_id, user_id).await?;

    let mut tx = pool.begin().await?;
    let rows = apps_data::delete(&mut *tx, app_id, data_id).await?;
    if rows == 0 {
        return Err(AppError::NotFound);
    }
    apps_access::bump_last_edit(&mut tx, app_id, user_id).await?;
    tx.commit().await?;
    Ok(())
}
