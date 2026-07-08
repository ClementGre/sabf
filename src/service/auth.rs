use chrono::{Duration, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::Config;
use crate::crypto;
use crate::error::{AppError, AppResult};
use crate::models::User;
use crate::repository::{sessions, users};

pub struct LoginResult {
    pub access_token: String,
    pub refresh_token: String,
    pub kdf_salt: Vec<u8>,
    pub kdf_params: Value,
    pub wrapped_umk: Vec<u8>,
    pub wrapped_privkey: Vec<u8>,
    pub public_key: Vec<u8>,
}

pub struct RefreshResult {
    pub access_token: String,
    pub refresh_token: String,
}

#[allow(clippy::too_many_arguments)]
pub async fn register(
    pool: &PgPool,
    username: &str,
    auth_key: &[u8],
    kdf_salt: &[u8],
    wrapped_umk: &[u8],
    public_key: &[u8],
    wrapped_privkey: &[u8],
) -> AppResult<User> {
    if users::find_by_username(pool, username).await?.is_some() {
        return Err(AppError::Conflict("username already taken".into()));
    }

    let id = Uuid::now_v7();
    let auth_salt = crypto::generate_auth_salt();
    let auth_hash = crypto::hash_auth_key(auth_key, &auth_salt)?;
    let kdf_params = crypto::current_kdf_params();

    let user = users::create(
        pool,
        id,
        username,
        &auth_hash,
        &auth_salt,
        kdf_salt,
        &kdf_params,
        wrapped_umk,
        public_key,
        wrapped_privkey,
    )
    .await?;
    Ok(user)
}

pub async fn login(pool: &PgPool, config: &Config, username: &str, auth_key: &[u8]) -> AppResult<LoginResult> {
    let user = users::find_by_username(pool, username)
        .await?
        .ok_or(AppError::Unauthorized)?;

    if !crypto::verify_auth_key(auth_key, &user.auth_salt, &user.auth_hash)? {
        return Err(AppError::Unauthorized);
    }

    let session_id = Uuid::now_v7();
    let refresh_token = crypto::generate_refresh_token();
    let refresh_token_hash = crypto::hash_refresh_token(&refresh_token);
    let expires_at = Utc::now() + Duration::seconds(config.refresh_token_ttl_secs);

    sessions::create(pool, session_id, user.id, &refresh_token_hash, None, expires_at).await?;

    let access_token =
        crypto::encode_access_token(user.id, session_id, config.access_token_ttl_secs, &config.jwt_secret)?;

    Ok(LoginResult {
        access_token,
        refresh_token,
        kdf_salt: user.kdf_salt,
        kdf_params: user.kdf_params,
        wrapped_umk: user.wrapped_umk,
        wrapped_privkey: user.wrapped_privkey,
        public_key: user.public_key,
    })
}

pub async fn refresh(pool: &PgPool, config: &Config, refresh_token: &str) -> AppResult<RefreshResult> {
    let refresh_token_hash = crypto::hash_refresh_token(refresh_token);
    let session = sessions::find_by_refresh_hash(pool, &refresh_token_hash)
        .await?
        .ok_or(AppError::Unauthorized)?;

    if session.revoked_at.is_some() {
        // Reuse of an already-consumed (or otherwise revoked) refresh token
        // is treated as a theft signal: nuke the whole lineage (SPEC.md §6).
        sessions::revoke_lineage(pool, session.id).await?;
        return Err(AppError::Unauthorized);
    }
    if session.expires_at < Utc::now() {
        return Err(AppError::Unauthorized);
    }

    let new_session_id = Uuid::now_v7();
    let new_refresh_token = crypto::generate_refresh_token();
    let new_refresh_token_hash = crypto::hash_refresh_token(&new_refresh_token);
    let expires_at = Utc::now() + Duration::seconds(config.refresh_token_ttl_secs);

    sessions::create(
        pool,
        new_session_id,
        session.user_id,
        &new_refresh_token_hash,
        Some(session.id),
        expires_at,
    )
    .await?;
    sessions::revoke(pool, session.id).await?;

    let access_token = crypto::encode_access_token(
        session.user_id,
        new_session_id,
        config.access_token_ttl_secs,
        &config.jwt_secret,
    )?;

    Ok(RefreshResult {
        access_token,
        refresh_token: new_refresh_token,
    })
}

pub async fn logout(pool: &PgPool, refresh_token: &str) -> AppResult<()> {
    let refresh_token_hash = crypto::hash_refresh_token(refresh_token);
    if let Some(session) = sessions::find_by_refresh_hash(pool, &refresh_token_hash).await? {
        sessions::revoke(pool, session.id).await?;
    }
    Ok(())
}

pub async fn change_passphrase(
    pool: &PgPool,
    user_id: Uuid,
    current_session_id: Uuid,
    current_auth_key: &[u8],
    new_auth_key: &[u8],
    new_kdf_salt: &[u8],
    new_wrapped_umk: &[u8],
) -> AppResult<()> {
    let user = users::find_by_id(pool, user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    if !crypto::verify_auth_key(current_auth_key, &user.auth_salt, &user.auth_hash)? {
        return Err(AppError::Unauthorized);
    }

    let new_auth_salt = crypto::generate_auth_salt();
    let new_auth_hash = crypto::hash_auth_key(new_auth_key, &new_auth_salt)?;

    users::update_passphrase(pool, user_id, &new_auth_hash, &new_auth_salt, new_kdf_salt, new_wrapped_umk).await?;
    sessions::revoke_all_for_user_except(pool, user_id, current_session_id).await?;
    Ok(())
}
