use sqlx::PgPool;
use uuid::Uuid;

use crate::crypto;
use crate::error::{AppError, AppResult};
use crate::models::User;
use crate::repository::users;

pub async fn get_me(pool: &PgPool, user_id: Uuid) -> AppResult<User> {
    users::find_by_id(pool, user_id).await?.ok_or(AppError::NotFound)
}

pub async fn get_by_username(pool: &PgPool, username: &str) -> AppResult<User> {
    users::find_by_username(pool, username)
        .await?
        .ok_or(AppError::NotFound)
}

/// Verifies the current passphrase, then deletes the account. Cascades to
/// owned apps (+ their data + grantee access), the user's own access rows on
/// shared apps, and all sessions — handled entirely by DB foreign-key
/// cascades (SPEC.md §5).
pub async fn delete_me(pool: &PgPool, user_id: Uuid, current_auth_key: &[u8]) -> AppResult<()> {
    let user = users::find_by_id(pool, user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    if !crypto::verify_auth_key(current_auth_key, &user.auth_salt, &user.auth_hash)? {
        return Err(AppError::Unauthorized);
    }

    users::delete(pool, user_id).await?;
    Ok(())
}
