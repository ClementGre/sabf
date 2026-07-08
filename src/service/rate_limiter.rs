//! Minimal in-memory sliding-window limiter for login attempts (SPEC.md §7).
//! Single-instance only — acceptable for a self-hosted deployment.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    max_attempts: u32,
    window: Duration,
    hits: Mutex<HashMap<String, Vec<Instant>>>,
}

impl RateLimiter {
    pub fn new(max_attempts: u32, window_secs: u64) -> Self {
        RateLimiter {
            max_attempts,
            window: Duration::from_secs(window_secs),
            hits: Mutex::new(HashMap::new()),
        }
    }

    /// Records an attempt for `key` and returns `true` if it should be
    /// allowed, `false` if the key is currently over the limit.
    pub fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut hits = self.hits.lock().expect("rate limiter mutex poisoned");
        let entry = hits.entry(key.to_string()).or_default();
        entry.retain(|t| now.duration_since(*t) < self.window);
        if entry.len() as u32 >= self.max_attempts {
            return false;
        }
        entry.push(now);
        true
    }
}
