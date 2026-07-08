use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use uuid::Uuid;

use crate::crypto;
use crate::error::AppError;
use crate::state::AppState;

/// Extracts and validates the `Authorization: Bearer <jwt>` access token.
pub struct AuthUser {
    pub user_id: Uuid,
    pub session_id: Uuid,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::Unauthorized)?;
        let token = header.strip_prefix("Bearer ").ok_or(AppError::Unauthorized)?;
        let claims = crypto::decode_access_token(token, &state.config().jwt_secret)
            .map_err(|_| AppError::Unauthorized)?;
        Ok(AuthUser {
            user_id: claims.sub,
            session_id: claims.sid,
        })
    }
}
