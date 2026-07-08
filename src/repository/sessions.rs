use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::Session;

pub async fn create(
    pool: &PgPool,
    id: Uuid,
    user_id: Uuid,
    refresh_token_hash: &str,
    parent_id: Option<Uuid>,
    expires_at: DateTime<Utc>,
) -> sqlx::Result<Session> {
    sqlx::query_as!(
        Session,
        r#"
        INSERT INTO sessions (id, user_id, refresh_token_hash, parent_id, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, user_id, refresh_token_hash, parent_id, created_at, expires_at, revoked_at
        "#,
        id,
        user_id,
        refresh_token_hash,
        parent_id,
        expires_at,
    )
    .fetch_one(pool)
    .await
}

pub async fn find_by_refresh_hash(
    pool: &PgPool,
    refresh_token_hash: &str,
) -> sqlx::Result<Option<Session>> {
    sqlx::query_as!(
        Session,
        r#"
        SELECT id, user_id, refresh_token_hash, parent_id, created_at, expires_at, revoked_at
        FROM sessions WHERE refresh_token_hash = $1
        "#,
        refresh_token_hash,
    )
    .fetch_optional(pool)
    .await
}

pub async fn revoke(pool: &PgPool, id: Uuid) -> sqlx::Result<()> {
    sqlx::query!(
        "UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
        id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn revoke_all_for_user_except(
    pool: &PgPool,
    user_id: Uuid,
    except_session_id: Uuid,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        UPDATE sessions SET revoked_at = now()
        WHERE user_id = $1 AND id != $2 AND revoked_at IS NULL
        "#,
        user_id,
        except_session_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Revokes the entire rotation lineage a session belongs to (both ancestors
/// and descendants via `parent_id`), used as the reuse-detection response
/// when a consumed refresh token is presented again (SPEC.md §6).
pub async fn revoke_lineage(pool: &PgPool, session_id: Uuid) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        WITH RECURSIVE lineage AS (
            SELECT id, parent_id FROM sessions WHERE id = $1
            UNION
            SELECT s.id, s.parent_id
            FROM sessions s
            JOIN lineage l ON s.id = l.parent_id OR s.parent_id = l.id
        )
        UPDATE sessions SET revoked_at = now()
        WHERE id IN (SELECT id FROM lineage) AND revoked_at IS NULL
        "#,
        session_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}
