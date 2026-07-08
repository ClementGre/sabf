use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::AppData;

pub async fn create(
    executor: impl sqlx::PgExecutor<'_>,
    id: Uuid,
    app_id: Uuid,
    r#type: &str,
    encrypted_json: &[u8],
) -> sqlx::Result<AppData> {
    sqlx::query_as!(
        AppData,
        r#"
        INSERT INTO apps_data (id, app_id, type, encrypted_json)
        VALUES ($1, $2, $3, $4)
        RETURNING id, app_id, type, encrypted_json, created_at, edited_at
        "#,
        id,
        app_id,
        r#type,
        encrypted_json,
    )
    .fetch_one(executor)
    .await
}

pub async fn update(
    executor: impl sqlx::PgExecutor<'_>,
    app_id: Uuid,
    data_id: Uuid,
    encrypted_json: &[u8],
) -> sqlx::Result<Option<AppData>> {
    sqlx::query_as!(
        AppData,
        r#"
        UPDATE apps_data SET encrypted_json = $3, edited_at = now()
        WHERE app_id = $1 AND id = $2
        RETURNING id, app_id, type, encrypted_json, created_at, edited_at
        "#,
        app_id,
        data_id,
        encrypted_json,
    )
    .fetch_optional(executor)
    .await
}

pub async fn delete(executor: impl sqlx::PgExecutor<'_>, app_id: Uuid, data_id: Uuid) -> sqlx::Result<u64> {
    let result = sqlx::query!(
        "DELETE FROM apps_data WHERE app_id = $1 AND id = $2",
        app_id,
        data_id,
    )
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}

pub struct ListFilters<'a> {
    pub r#type: Option<&'a str>,
    pub created_from: Option<DateTime<Utc>>,
    pub created_to: Option<DateTime<Utc>>,
    pub edited_from: Option<DateTime<Utc>>,
    pub edited_to: Option<DateTime<Utc>>,
    pub cursor: Option<(DateTime<Utc>, Uuid)>,
    pub limit: i64,
}

pub async fn list(
    pool: &PgPool,
    app_id: Uuid,
    filters: &ListFilters<'_>,
) -> sqlx::Result<Vec<AppData>> {
    let (cursor_created_at, cursor_id) = match filters.cursor {
        Some((created_at, id)) => (Some(created_at), Some(id)),
        None => (None, None),
    };
    sqlx::query_as!(
        AppData,
        r#"
        SELECT id, app_id, type, encrypted_json, created_at, edited_at
        FROM apps_data
        WHERE app_id = $1
          AND ($2::text IS NULL OR type = $2)
          AND ($3::timestamptz IS NULL OR created_at >= $3)
          AND ($4::timestamptz IS NULL OR created_at <= $4)
          AND ($5::timestamptz IS NULL OR edited_at >= $5)
          AND ($6::timestamptz IS NULL OR edited_at <= $6)
          AND ($7::timestamptz IS NULL OR (created_at, id) > ($7, $8))
        ORDER BY created_at, id
        LIMIT $9
        "#,
        app_id,
        filters.r#type,
        filters.created_from,
        filters.created_to,
        filters.edited_from,
        filters.edited_to,
        cursor_created_at,
        cursor_id,
        filters.limit,
    )
    .fetch_all(pool)
    .await
}

/// Overwrites ciphertext in place during rotation (SPEC.md §3.1).
/// `edited_at`/`created_at` are intentionally left untouched: re-encryption
/// under a new DEK is not a content edit.
pub async fn replace_ciphertext_for_rotate(
    tx: &mut sqlx::PgConnection,
    app_id: Uuid,
    data_id: Uuid,
    encrypted_json: &[u8],
) -> sqlx::Result<u64> {
    let result = sqlx::query!(
        "UPDATE apps_data SET encrypted_json = $3 WHERE app_id = $1 AND id = $2",
        app_id,
        data_id,
        encrypted_json,
    )
    .execute(tx)
    .await?;
    Ok(result.rows_affected())
}
