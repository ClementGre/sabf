use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{App, AppWithAccess};

pub async fn create(
    executor: impl sqlx::PgExecutor<'_>,
    id: Uuid,
    owner_id: Uuid,
    slug: &str,
    encrypted_metadata: &[u8],
) -> sqlx::Result<App> {
    sqlx::query_as!(
        App,
        r#"
        INSERT INTO apps (id, owner_id, slug, encrypted_metadata)
        VALUES ($1, $2, $3, $4)
        RETURNING id, owner_id, slug, encrypted_metadata, created_at
        "#,
        id,
        owner_id,
        slug,
        encrypted_metadata,
    )
    .fetch_one(executor)
    .await
}

pub async fn find_by_id(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<App>> {
    sqlx::query_as!(
        App,
        "SELECT id, owner_id, slug, encrypted_metadata, created_at FROM apps WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await
}

pub async fn update_metadata(
    tx: &mut sqlx::PgConnection,
    id: Uuid,
    encrypted_metadata: &[u8],
) -> sqlx::Result<()> {
    sqlx::query!(
        "UPDATE apps SET encrypted_metadata = $2 WHERE id = $1",
        id,
        encrypted_metadata,
    )
    .execute(tx)
    .await?;
    Ok(())
}

pub async fn delete(pool: &PgPool, id: Uuid) -> sqlx::Result<()> {
    sqlx::query!("DELETE FROM apps WHERE id = $1", id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Caller's active memberships joined with apps, optionally filtered by slug.
pub async fn list_active_for_user(
    pool: &PgPool,
    user_id: Uuid,
    slug: Option<&str>,
) -> sqlx::Result<Vec<AppWithAccess>> {
    sqlx::query_as!(
        AppWithAccess,
        r#"
        SELECT a.id AS app_id, a.slug, a.encrypted_metadata,
               aa.role, aa.status, aa.wrapped_dek, aa.last_edit_at
        FROM apps_access aa
        JOIN apps a ON a.id = aa.app_id
        WHERE aa.user_id = $1 AND aa.status = 'active'
          AND ($2::text IS NULL OR a.slug = $2)
        ORDER BY a.created_at
        "#,
        user_id,
        slug,
    )
    .fetch_all(pool)
    .await
}

/// A single app joined with the caller's membership row, any status
/// (service layer decides what pending members may see).
pub async fn find_with_access_for_user(
    pool: &PgPool,
    app_id: Uuid,
    user_id: Uuid,
) -> sqlx::Result<Option<AppWithAccess>> {
    sqlx::query_as!(
        AppWithAccess,
        r#"
        SELECT a.id AS app_id, a.slug, a.encrypted_metadata,
               aa.role, aa.status, aa.wrapped_dek, aa.last_edit_at
        FROM apps_access aa
        JOIN apps a ON a.id = aa.app_id
        WHERE aa.app_id = $1 AND aa.user_id = $2
        "#,
        app_id,
        user_id,
    )
    .fetch_optional(pool)
    .await
}
