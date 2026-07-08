//! Row structs mirroring the schema in migrations/0001_init.sql.

use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub auth_hash: String,
    pub auth_salt: Vec<u8>,
    pub kdf_salt: Vec<u8>,
    pub kdf_params: Value,
    pub wrapped_umk: Vec<u8>,
    pub public_key: Vec<u8>,
    pub wrapped_privkey: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[allow(dead_code)] // full row shape kept for schema fidelity; not every column is read back
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub refresh_token_hash: String,
    pub parent_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct App {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub slug: String,
    pub encrypted_metadata: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AppAccess {
    pub app_id: Uuid,
    pub user_id: Uuid,
    pub wrapped_dek: Vec<u8>,
    pub role: String,
    pub status: String,
    pub last_edit_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// A membership row joined with its app — the shape `GET /apps` returns.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AppWithAccess {
    pub app_id: Uuid,
    pub slug: String,
    pub encrypted_metadata: Vec<u8>,
    pub role: String,
    pub status: String,
    pub wrapped_dek: Vec<u8>,
    pub last_edit_at: Option<DateTime<Utc>>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AppData {
    pub id: Uuid,
    pub app_id: Uuid,
    pub r#type: String,
    pub encrypted_json: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub edited_at: DateTime<Utc>,
}
