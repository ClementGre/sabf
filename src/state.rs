use std::sync::Arc;

use sqlx::PgPool;

use crate::config::Config;
use crate::service::rate_limiter::RateLimiter;

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

struct Inner {
    pub pool: PgPool,
    pub config: Config,
    pub login_rate_limiter: RateLimiter,
}

impl AppState {
    pub fn new(pool: PgPool, config: Config) -> Self {
        let login_rate_limiter = RateLimiter::new(
            config.login_rate_limit_max_attempts,
            config.login_rate_limit_window_secs,
        );
        AppState(Arc::new(Inner {
            pool,
            config,
            login_rate_limiter,
        }))
    }

    pub fn pool(&self) -> &PgPool {
        &self.0.pool
    }

    pub fn config(&self) -> &Config {
        &self.0.config
    }

    pub fn login_rate_limiter(&self) -> &RateLimiter {
        &self.0.login_rate_limiter
    }
}
