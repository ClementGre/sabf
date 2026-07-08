use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::AppWithAccess;
use crate::repository::{apps, apps_access, apps_data, audit};

pub async fn create_app(
    pool: &PgPool,
    owner_id: Uuid,
    app_id: Uuid,
    slug: &str,
    encrypted_metadata: &[u8],
    wrapped_dek: &[u8],
) -> AppResult<AppWithAccess> {
    let mut tx = pool.begin().await?;
    let app = apps::create(&mut *tx, app_id, owner_id, slug, encrypted_metadata).await?;
    let access = apps_access::create(&mut tx, app.id, owner_id, wrapped_dek, "owner", "active").await?;
    tx.commit().await?;

    Ok(AppWithAccess {
        app_id: app.id,
        slug: app.slug,
        encrypted_metadata: app.encrypted_metadata,
        role: access.role,
        status: access.status,
        wrapped_dek: access.wrapped_dek,
        last_edit_at: access.last_edit_at,
    })
}

pub async fn list_apps(pool: &PgPool, user_id: Uuid, slug: Option<&str>) -> AppResult<Vec<AppWithAccess>> {
    Ok(apps::list_active_for_user(pool, user_id, slug).await?)
}

pub async fn get_app(pool: &PgPool, app_id: Uuid, user_id: Uuid) -> AppResult<AppWithAccess> {
    let row = apps::find_with_access_for_user(pool, app_id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if row.status != "active" {
        return Err(AppError::Forbidden);
    }
    Ok(row)
}

pub async fn patch_metadata(
    pool: &PgPool,
    app_id: Uuid,
    user_id: Uuid,
    encrypted_metadata: &[u8],
) -> AppResult<()> {
    let access = apps_access::find(pool, app_id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if access.status != "active" {
        return Err(AppError::Forbidden);
    }

    let mut tx = pool.begin().await?;
    apps::update_metadata(&mut tx, app_id, encrypted_metadata).await?;
    apps_access::bump_last_edit(&mut tx, app_id, user_id).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn delete_app(pool: &PgPool, app_id: Uuid, user_id: Uuid) -> AppResult<()> {
    let app = apps::find_by_id(pool, app_id).await?.ok_or(AppError::NotFound)?;
    if app.owner_id != user_id {
        return Err(AppError::Forbidden);
    }
    apps::delete(pool, app_id).await?;
    audit::log(pool, Some(user_id), "app.delete", Some(app_id), None).await?;
    Ok(())
}

pub async fn leave_app(pool: &PgPool, app_id: Uuid, user_id: Uuid) -> AppResult<()> {
    let access = apps_access::find(pool, app_id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if access.role == "owner" {
        return Err(AppError::BadRequest(
            "the owner cannot leave; delete the app or rotate access instead".into(),
        ));
    }
    apps_access::remove(pool, app_id, user_id).await?;
    audit::log(pool, Some(user_id), "leave", Some(app_id), None).await?;
    Ok(())
}

pub struct RotateDataItem {
    pub id: Uuid,
    pub new_encrypted_json: Vec<u8>,
}

pub struct RotateAccessItem {
    pub user_id: Uuid,
    pub new_wrapped_dek: Vec<u8>,
}

pub async fn rotate(
    pool: &PgPool,
    app_id: Uuid,
    owner_id: Uuid,
    new_encrypted_metadata: &[u8],
    data: Vec<RotateDataItem>,
    access: Vec<RotateAccessItem>,
) -> AppResult<()> {
    let app = apps::find_by_id(pool, app_id).await?.ok_or(AppError::NotFound)?;
    if app.owner_id != owner_id {
        return Err(AppError::Forbidden);
    }
    if !access.iter().any(|a| a.user_id == owner_id) {
        return Err(AppError::BadRequest(
            "the access list must include the owner's own re-sealed DEK".into(),
        ));
    }

    let mut tx = pool.begin().await?;
    apps::update_metadata(&mut tx, app_id, new_encrypted_metadata).await?;
    for item in &data {
        let rows = apps_data::replace_ciphertext_for_rotate(&mut tx, app_id, item.id, &item.new_encrypted_json)
            .await?;
        if rows == 0 {
            return Err(AppError::BadRequest(format!(
                "data row {} does not belong to this app",
                item.id
            )));
        }
    }
    let access_pairs: Vec<(Uuid, Vec<u8>)> = access
        .into_iter()
        .map(|a| (a.user_id, a.new_wrapped_dek))
        .collect();
    apps_access::replace_for_rotate(&mut tx, app_id, owner_id, &access_pairs).await?;
    audit::log(&mut *tx, Some(owner_id), "rotate", Some(app_id), None).await?;
    tx.commit().await?;
    Ok(())
}
