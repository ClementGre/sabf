//! Server-side crypto only. Per the zero-knowledge design (SPEC.md §1/§2), the
//! server never touches content encryption (DEK/UMK/privkey wrapping, sealed
//! boxes) — that all happens client-side. What's left for the server is:
//! the login-verifier hash, JWT access tokens, and opaque refresh tokens.

use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Framework-fixed Argon2id cost parameters (SPEC.md §7). A single constant
/// shared by both the client-side KDF params we hand out and the
/// server-side login-verifier hash. `version` lets a future framework
/// release roll these forward without breaking existing users.
const KDF_VERSION: u32 = 1;
const KDF_MEM_COST_KIB: u32 = 19_456;
const KDF_TIME_COST: u32 = 2;
const KDF_PARALLELISM: u32 = 1;
const HASH_LEN: usize = 32;

fn argon2() -> Argon2<'static> {
    let params = Params::new(KDF_MEM_COST_KIB, KDF_TIME_COST, KDF_PARALLELISM, Some(HASH_LEN))
        .expect("static argon2 params are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// The fixed KDF params advertised to clients for client-side passphrase
/// stretching (stored in `users.kdf_params`, returned at register/login).
pub fn current_kdf_params() -> Value {
    json!({
        "algorithm": "argon2id",
        "version": KDF_VERSION,
        "mem_cost_kib": KDF_MEM_COST_KIB,
        "time_cost": KDF_TIME_COST,
        "parallelism": KDF_PARALLELISM,
    })
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::rng().fill_bytes(&mut buf);
    buf
}

pub fn generate_auth_salt() -> Vec<u8> {
    random_bytes(16)
}

/// `auth_hash = Argon2id(auth_key, auth_salt)`, the server-side verifier
/// hash (SPEC.md §3). Returned as base64, stored verbatim in `users.auth_hash`.
pub fn hash_auth_key(auth_key: &[u8], auth_salt: &[u8]) -> Result<String> {
    let mut out = [0u8; HASH_LEN];
    argon2()
        .hash_password_into(auth_key, auth_salt, &mut out)
        .map_err(|e| anyhow::anyhow!("argon2 hash failed: {e}"))?;
    Ok(STANDARD.encode(out))
}

pub fn verify_auth_key(auth_key: &[u8], auth_salt: &[u8], expected_hash: &str) -> Result<bool> {
    let computed = hash_auth_key(auth_key, auth_salt)?;
    Ok(constant_time_eq(computed.as_bytes(), expected_hash.as_bytes()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Opaque 32-byte random refresh token, URL-safe base64 encoded on the wire.
pub fn generate_refresh_token() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes(32))
}

/// Refresh tokens are stored only as a SHA-256 hash (SPEC.md §6).
pub fn hash_refresh_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex::encode(digest)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessClaims {
    pub sub: Uuid,
    pub sid: Uuid,
    pub iat: i64,
    pub exp: i64,
}

pub fn encode_access_token(
    user_id: Uuid,
    session_id: Uuid,
    ttl_secs: i64,
    secret: &[u8],
) -> Result<String> {
    let now = chrono::Utc::now().timestamp();
    let claims = AccessClaims {
        sub: user_id,
        sid: session_id,
        iat: now,
        exp: now + ttl_secs,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret))
        .context("failed to encode access token")
}

pub fn decode_access_token(token: &str, secret: &[u8]) -> Result<AccessClaims> {
    let data = decode::<AccessClaims>(
        token,
        &DecodingKey::from_secret(secret),
        &Validation::default(),
    )
    .context("invalid or expired access token")?;
    Ok(data.claims)
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}
