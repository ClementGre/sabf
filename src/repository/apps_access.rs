use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::AppAccess;

pub async fn create(
    tx: &mut sqlx::PgConnection,
    app_id: Uuid,
    user_id: Uuid,
    wrapped_dek: &[u8],
    role: &str,
    status: &str,
) -> sqlx::Result<AppAccess> {
    sqlx::query_as!(
        AppAccess,
        r#"
        INSERT INTO apps_access (app_id, user_id, wrapped_dek, role, status)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING app_id, user_id, wrapped_dek, role, status, last_edit_at, created_at
        "#,
        app_id,
        user_id,
        wrapped_dek,
        role,
        status,
    )
    .fetch_one(tx)
    .await
}

pub async fn find(
    pool: &PgPool,
    app_id: Uuid,
    user_id: Uuid,
) -> sqlx::Result<Option<AppAccess>> {
    sqlx::query_as!(
        AppAccess,
        r#"
        SELECT app_id, user_id, wrapped_dek, role, status, last_edit_at, created_at
        FROM apps_access WHERE app_id = $1 AND user_id = $2
        "#,
        app_id,
        user_id,
    )
    .fetch_optional(pool)
    .await
}

pub async fn list_for_app(pool: &PgPool, app_id: Uuid) -> sqlx::Result<Vec<AppAccess>> {
    sqlx::query_as!(
        AppAccess,
        r#"
        SELECT app_id, user_id, wrapped_dek, role, status, last_edit_at, created_at
        FROM apps_access WHERE app_id = $1
        ORDER BY created_at
        "#,
        app_id,
    )
    .fetch_all(pool)
    .await
}

pub struct PendingShare {
    pub app_id: Uuid,
    pub slug: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

/// Caller's incoming pending shares. `wrapped_dek` is intentionally excluded
/// (SPEC.md §3/§5) — an honest server never hands out the sealed DEK to a
/// recipient who hasn't accepted yet.
pub async fn list_pending_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> sqlx::Result<Vec<PendingShare>> {
    sqlx::query_as!(
        PendingShare,
        r#"
        SELECT aa.app_id, a.slug, aa.role, aa.created_at
        FROM apps_access aa
        JOIN apps a ON a.id = aa.app_id
        WHERE aa.user_id = $1 AND aa.status = 'pending'
        ORDER BY aa.created_at
        "#,
        user_id,
    )
    .fetch_all(pool)
    .await
}

pub async fn accept(
    executor: impl sqlx::PgExecutor<'_>,
    app_id: Uuid,
    user_id: Uuid,
) -> sqlx::Result<Option<AppAccess>> {
    sqlx::query_as!(
        AppAccess,
        r#"
        UPDATE apps_access SET status = 'active'
        WHERE app_id = $1 AND user_id = $2 AND status = 'pending'
        RETURNING app_id, user_id, wrapped_dek, role, status, last_edit_at, created_at
        "#,
        app_id,
        user_id,
    )
    .fetch_optional(executor)
    .await
}

pub async fn remove(executor: impl sqlx::PgExecutor<'_>, app_id: Uuid, user_id: Uuid) -> sqlx::Result<()> {
    sqlx::query!(
        "DELETE FROM apps_access WHERE app_id = $1 AND user_id = $2",
        app_id,
        user_id,
    )
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn bump_last_edit(
    tx: &mut sqlx::PgConnection,
    app_id: Uuid,
    user_id: Uuid,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        UPDATE apps_access SET last_edit_at = now()
        WHERE app_id = $1 AND user_id = $2
        "#,
        app_id,
        user_id,
    )
    .execute(tx)
    .await?;
    Ok(())
}

/// Replaces the full access set for an app within a rotation transaction
/// (SPEC.md §3.1): deletes all rows, inserts exactly the submitted set. The
/// owner's row is re-created with role='owner'; everyone else is 'member'.
pub async fn replace_for_rotate(
    tx: &mut sqlx::PgConnection,
    app_id: Uuid,
    owner_id: Uuid,
    access: &[(Uuid, Vec<u8>)],
) -> sqlx::Result<()> {
    sqlx::query!("DELETE FROM apps_access WHERE app_id = $1", app_id)
        .execute(&mut *tx)
        .await?;
    for (user_id, wrapped_dek) in access {
        let role = if *user_id == owner_id { "owner" } else { "member" };
        sqlx::query!(
            r#"
            INSERT INTO apps_access (app_id, user_id, wrapped_dek, role, status)
            VALUES ($1, $2, $3, $4, 'active')
            "#,
            app_id,
            user_id,
            wrapped_dek,
            role,
        )
        .execute(&mut *tx)
        .await?;
    }
    Ok(())
}
