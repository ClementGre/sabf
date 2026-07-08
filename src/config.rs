use rand::RngCore;
use std::env;

/// CORS allow-list, parsed from `CORS_ALLOWED_ORIGINS`: either `*` (any
/// origin) or a comma-separated list of exact frontend origins.
#[derive(Clone)]
pub enum CorsOrigins {
    Any,
    List(Vec<String>),
}

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub host: String,
    pub port: u16,
    pub jwt_secret: Vec<u8>,
    pub access_token_ttl_secs: i64,
    pub refresh_token_ttl_secs: i64,
    pub login_rate_limit_max_attempts: u32,
    pub login_rate_limit_window_secs: u64,
    pub cors_allowed_origins: CorsOrigins,
}

impl Config {
    pub fn from_env() -> Self {
        let jwt_secret = match env::var("JWT_SECRET") {
            Ok(s) if !s.is_empty() => s.into_bytes(),
            _ => {
                tracing::warn!(
                    "JWT_SECRET not set; generating a random secret for this process \
                     (all existing access tokens will be invalidated on restart)"
                );
                let mut buf = [0u8; 32];
                rand::rng().fill_bytes(&mut buf);
                buf.to_vec()
            }
        };

        Config {
            database_url: env::var("DATABASE_URL").expect("DATABASE_URL must be set"),
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(80),
            jwt_secret,
            access_token_ttl_secs: env::var("ACCESS_TOKEN_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(900),
            refresh_token_ttl_secs: env::var("REFRESH_TOKEN_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2_592_000),
            login_rate_limit_max_attempts: env::var("LOGIN_RATE_LIMIT_MAX_ATTEMPTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
            login_rate_limit_window_secs: env::var("LOGIN_RATE_LIMIT_WINDOW_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            cors_allowed_origins: match env::var("CORS_ALLOWED_ORIGINS") {
                Ok(v) if v.trim() == "*" => CorsOrigins::Any,
                Ok(v) if !v.trim().is_empty() => CorsOrigins::List(
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect(),
                ),
                _ => {
                    tracing::warn!(
                        "CORS_ALLOWED_ORIGINS not set; no cross-origin requests will be allowed"
                    );
                    CorsOrigins::List(Vec::new())
                }
            },
        }
    }
}
