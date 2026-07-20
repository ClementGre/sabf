//! Minimal in-memory sliding-window limiter for login attempts (SPEC.md §7).
//! Single-instance only — acceptable for a self-hosted deployment.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Hard cap on the number of distinct keys tracked at once. Keys are derived
/// from the attacker-controlled username (`user:<name>`) and source IP, so
/// without a bound a flood of distinct usernames would grow the map without
/// limit (memory-exhaustion DoS). When the cap is exceeded we sweep keys whose
/// window has fully elapsed; this bounds live memory to roughly
/// `MAX_TRACKED_KEYS * max_attempts` timestamps.
const MAX_TRACKED_KEYS: usize = 100_000;

pub struct RateLimiter {
    max_attempts: u32,
    window: Duration,
    max_keys: usize,
    hits: Mutex<HashMap<String, Vec<Instant>>>,
}

impl RateLimiter {
    pub fn new(max_attempts: u32, window_secs: u64) -> Self {
        RateLimiter {
            max_attempts,
            window: Duration::from_secs(window_secs),
            max_keys: MAX_TRACKED_KEYS,
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
        let allowed = if entry.len() as u32 >= self.max_attempts {
            false
        } else {
            entry.push(now);
            true
        };

        // Bound memory: only when the map has grown past the cap do we pay for
        // a full sweep, dropping every key whose attempts have all aged out.
        if hits.len() > self.max_keys {
            hits.retain(|_, timestamps| {
                timestamps.retain(|t| now.duration_since(*t) < self.window);
                !timestamps.is_empty()
            });
        }

        allowed
    }
}
