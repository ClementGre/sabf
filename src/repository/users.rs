use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::User;

#[allow(clippy::too_many_arguments)]
pub async fn create(
    pool: &PgPool,
    id: Uuid,
    username: &str,
    auth_hash: &str,
    auth_salt: &[u8],
    kdf_salt: &[u8],
    kdf_params: &Value,
    wrapped_umk: &[u8],
    public_key: &[u8],
    wrapped_privkey: &[u8],
) -> sqlx::Result<User> {
    sqlx::query_as!(
        User,
        r#"
        INSERT INTO users
            (id, username, auth_hash, auth_salt, kdf_salt, kdf_params,
             wrapped_umk, public_key, wrapped_privkey)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id, username, auth_hash, auth_salt, kdf_salt, kdf_params,
                  wrapped_umk, public_key, wrapped_privkey, created_at
        "#,
        id,
        username,
        auth_hash,
        auth_salt,
        kdf_salt,
        kdf_params,
        wrapped_umk,
        public_key,
        wrapped_privkey,
    )
    .fetch_one(pool)
    .await
}

pub async fn find_by_username(pool: &PgPool, username: &str) -> sqlx::Result<Option<User>> {
    sqlx::query_as!(
        User,
        r#"
        SELECT id, username, auth_hash, auth_salt, kdf_salt, kdf_params,
               wrapped_umk, public_key, wrapped_privkey, created_at
        FROM users WHERE username = $1
        "#,
        username,
    )
    .fetch_optional(pool)
    .await
}

pub async fn find_by_id(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<User>> {
    sqlx::query_as!(
        User,
        r#"
        SELECT id, username, auth_hash, auth_salt, kdf_salt, kdf_params,
               wrapped_umk, public_key, wrapped_privkey, created_at
        FROM users WHERE id = $1
        "#,
        id,
    )
    .fetch_optional(pool)
    .await
}

pub async fn update_passphrase(
    pool: &PgPool,
    user_id: Uuid,
    new_auth_hash: &str,
    new_auth_salt: &[u8],
    new_kdf_salt: &[u8],
    new_wrapped_umk: &[u8],
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        UPDATE users
        SET auth_hash = $2, auth_salt = $3, kdf_salt = $4, wrapped_umk = $5
        WHERE id = $1
        "#,
        user_id,
        new_auth_hash,
        new_auth_salt,
        new_kdf_salt,
        new_wrapped_umk,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete(pool: &PgPool, user_id: Uuid) -> sqlx::Result<()> {
    sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
        .execute(pool)
        .await?;
    Ok(())
}
