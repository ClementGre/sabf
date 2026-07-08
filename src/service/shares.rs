use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::AppAccess;
use crate::repository::{apps, apps_access, audit, users};
use crate::repository::apps_access::PendingShare;

pub async fn create_share(
    pool: &PgPool,
    app_id: Uuid,
    owner_id: Uuid,
    recipient_user_id: Uuid,
    wrapped_dek: &[u8],
) -> AppResult<AppAccess> {
    let app = apps::find_by_id(pool, app_id).await?.ok_or(AppError::NotFound)?;
    if app.owner_id != owner_id {
        return Err(AppError::Forbidden);
    }
    if users::find_by_id(pool, recipient_user_id).await?.is_none() {
        return Err(AppError::BadRequest("recipient user does not exist".into()));
    }
    if apps_access::find(pool, app_id, recipient_user_id).await?.is_some() {
        return Err(AppError::Conflict(
            "recipient already has access or a pending invite".into(),
        ));
    }

    let mut tx = pool.begin().await?;
    let access = apps_access::create(&mut tx, app_id, recipient_user_id, wrapped_dek, "member", "pending").await?;
    audit::log(&mut *tx, Some(owner_id), "share", Some(app_id), Some(recipient_user_id)).await?;
    tx.commit().await?;
    Ok(access)
}

pub async fn list_shares(pool: &PgPool, app_id: Uuid, owner_id: Uuid) -> AppResult<Vec<AppAccess>> {
    let app = apps::find_by_id(pool, app_id).await?.ok_or(AppError::NotFound)?;
    if app.owner_id != owner_id {
        return Err(AppError::Forbidden);
    }
    Ok(apps_access::list_for_app(pool, app_id).await?)
}

pub async fn list_pending_for_user(pool: &PgPool, user_id: Uuid) -> AppResult<Vec<PendingShare>> {
    Ok(apps_access::list_pending_for_user(pool, user_id).await?)
}

pub async fn accept(pool: &PgPool, app_id: Uuid, user_id: Uuid) -> AppResult<AppAccess> {
    let mut tx = pool.begin().await?;
    let access = apps_access::accept(&mut *tx, app_id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    audit::log(&mut *tx, Some(user_id), "accept", Some(app_id), None).await?;
    tx.commit().await?;
    Ok(access)
}

pub async fn decline(pool: &PgPool, app_id: Uuid, user_id: Uuid) -> AppResult<()> {
    let access = apps_access::find(pool, app_id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if access.status != "pending" {
        return Err(AppError::BadRequest("no pending invite to decline".into()));
    }

    let mut tx = pool.begin().await?;
    apps_access::remove(&mut *tx, app_id, user_id).await?;
    audit::log(&mut *tx, Some(user_id), "decline", Some(app_id), None).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn remove_member(
    pool: &PgPool,
    app_id: Uuid,
    owner_id: Uuid,
    target_user_id: Uuid,
) -> AppResult<()> {
    let app = apps::find_by_id(pool, app_id).await?.ok_or(AppError::NotFound)?;
    if app.owner_id != owner_id {
        return Err(AppError::Forbidden);
    }
    if target_user_id == owner_id {
        return Err(AppError::BadRequest("the owner cannot remove their own access row".into()));
    }

    let mut tx = pool.begin().await?;
    apps_access::remove(&mut *tx, app_id, target_user_id).await?;
    audit::log(&mut *tx, Some(owner_id), "revoke", Some(app_id), Some(target_user_id)).await?;
    tx.commit().await?;
    Ok(())
}
