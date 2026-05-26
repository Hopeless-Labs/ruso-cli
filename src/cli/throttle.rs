//! Per-host concurrency and global RPS throttles for the scan pipeline.
//!
//! These sit between the global `-c / --concurrency` cap (which bounds total
//! in-flight scans) and `ruso_runtime` (which executes a single script).
//! They exist so a high global concurrency does not translate into hammering
//! a single sensitive host or launching scripts faster than a target tolerates.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Per-host concurrency cap. A scan against host `H` must hold one permit
/// from `H`'s semaphore for the duration of the run, so at most `limit`
/// scans against `H` are in flight at once regardless of the global pool.
#[derive(Default, Clone)]
pub struct HostThrottle {
    inner: Option<Arc<HostThrottleInner>>,
}

struct HostThrottleInner {
    limit: usize,
    slots: Mutex<HashMap<String, Arc<Semaphore>>>,
}

impl HostThrottle {
    pub fn new(limit: usize) -> Self {
        if limit == 0 {
            return Self::default();
        }
        Self {
            inner: Some(Arc::new(HostThrottleInner {
                limit,
                slots: Mutex::new(HashMap::new()),
            })),
        }
    }

    pub async fn acquire(&self, host: &str) -> HostPermit {
        let Some(inner) = &self.inner else {
            return HostPermit::Noop;
        };
        let sem = {
            let mut slots = inner.slots.lock().expect("host slots mutex poisoned");
            slots
                .entry(host.to_owned())
                .or_insert_with(|| Arc::new(Semaphore::new(inner.limit)))
                .clone()
        };
        let permit = sem
            .acquire_owned()
            .await
            .expect("host semaphore is never closed");
        HostPermit::Held(permit)
    }
}

/// RAII guard. Dropping releases the per-host permit (or is a no-op when the
/// throttle is disabled). The `OwnedSemaphorePermit` variant carries its own
/// `Arc<Semaphore>` ref, so the slot lives even if `HostThrottle` is dropped.
pub enum HostPermit {
    Noop,
    Held(#[allow(dead_code)] OwnedSemaphorePermit),
}

/// Global token-bucket rate limiter with capacity 1 (no burst). Tracks the
/// earliest `Instant` the next caller may proceed and sleeps the difference.
///
/// Capacity 1 means callers cannot stockpile unused budget — useful as a
/// safety cap. If burst behavior is ever wanted, widen `next_allowed` into a
/// running balance.
#[derive(Default, Clone)]
pub struct RateLimiter {
    inner: Option<Arc<RateLimiterInner>>,
}

struct RateLimiterInner {
    interval: Duration,
    next_allowed: Mutex<Instant>,
}

impl RateLimiter {
    pub fn per_second(rps: u32) -> Self {
        if rps == 0 {
            return Self::default();
        }
        let interval = Duration::from_nanos(1_000_000_000 / rps as u64);
        Self {
            inner: Some(Arc::new(RateLimiterInner {
                interval,
                next_allowed: Mutex::new(Instant::now()),
            })),
        }
    }

    pub async fn acquire(&self) {
        let Some(inner) = &self.inner else { return };
        let wait = {
            let mut next = inner.next_allowed.lock().expect("rps mutex poisoned");
            let now = Instant::now();
            let scheduled = (*next).max(now);
            let wait = scheduled.saturating_duration_since(now);
            *next = scheduled + inner.interval;
            wait
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

/// Best-effort host extraction from `http(s)://host[:port]/...`. Targets are
/// pre-validated by `discover_targets`, so unparseable input falls back to
/// the lowercased original string — different unparseable targets just bucket
/// together under the same key, which is harmless.
pub fn host_key(target: &str) -> String {
    let after_scheme = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .unwrap_or(target);
    let end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    after_scheme[..end].to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn host_key_extracts_authority() {
        assert_eq!(host_key("https://example.com/a/b"), "example.com");
        assert_eq!(host_key("http://EXAMPLE.com:8080/x"), "example.com:8080");
        assert_eq!(host_key("https://example.com"), "example.com");
        assert_eq!(host_key("https://example.com?q=1"), "example.com");
        assert_eq!(host_key("https://example.com#frag"), "example.com");
    }

    #[tokio::test]
    async fn host_throttle_disabled_when_zero() {
        let t = HostThrottle::new(0);
        // 100 simultaneous "acquires" against the same host must all proceed.
        let mut handles = Vec::new();
        for _ in 0..100 {
            let t = t.clone();
            handles.push(tokio::spawn(async move {
                let _g = t.acquire("h").await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    }

    #[tokio::test]
    async fn host_throttle_bounds_per_host_in_flight() {
        let t = HostThrottle::new(2);
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..20 {
            let t = t.clone();
            let in_flight = in_flight.clone();
            let peak = peak.clone();
            handles.push(tokio::spawn(async move {
                let _g = t.acquire("host-a").await;
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(peak.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn host_throttle_separates_distinct_hosts() {
        let t = HostThrottle::new(1);
        let _a = t.acquire("host-a").await;
        // A second acquire for `host-b` must not block on `host-a`'s permit.
        let acquired = tokio::time::timeout(Duration::from_millis(50), t.acquire("host-b")).await;
        assert!(acquired.is_ok(), "distinct hosts must not share a semaphore");
    }

    #[tokio::test]
    async fn rate_limiter_disabled_when_zero() {
        let r = RateLimiter::per_second(0);
        let start = Instant::now();
        for _ in 0..100 {
            r.acquire().await;
        }
        assert!(start.elapsed() < Duration::from_millis(20));
    }

    #[tokio::test]
    async fn rate_limiter_enforces_interval() {
        // 50 RPS = 20ms interval. 5 calls should take >= ~80ms (4 intervals).
        let r = RateLimiter::per_second(50);
        let start = Instant::now();
        for _ in 0..5 {
            r.acquire().await;
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(70),
            "expected >=70ms, got {elapsed:?}"
        );
    }
}
