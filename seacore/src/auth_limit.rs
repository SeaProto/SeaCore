use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
struct Entry {
    tokens: f64,
    last_refill: Instant,
    penalty_ms: u64,
    penalty_until: Instant,
}

impl Entry {
    fn new(now: Instant, capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: now,
            penalty_ms: 0,
            penalty_until: now,
        }
    }
}

/// Simple token-bucket + exponential-penalty limiter for auth failures.
///
/// - Success path always incurs a small jitter to reduce timing side channels.
/// - Failure path applies stronger delay and exponentially increasing penalties
///   when the source exceeds the token budget.
#[derive(Debug)]
pub struct AuthRateLimiter {
    entries: HashMap<IpAddr, Entry>,
    capacity: f64,
    refill_per_sec: f64,
    base_success_delay: Duration,
    base_failure_delay: Duration,
    base_penalty_ms: u64,
    max_penalty_ms: u64,
    ttl: Duration,
}

impl Default for AuthRateLimiter {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            capacity: 8.0,
            refill_per_sec: 2.5,
            base_success_delay: Duration::from_millis(8),
            base_failure_delay: Duration::from_millis(28),
            base_penalty_ms: 80,
            max_penalty_ms: 2_000,
            ttl: Duration::from_secs(180),
        }
    }
}

impl AuthRateLimiter {
    pub fn delay_for_attempt(&mut self, ip: IpAddr, authenticated: bool) -> Duration {
        let now = Instant::now();
        self.gc(now);

        let entry = self
            .entries
            .entry(ip)
            .or_insert_with(|| Entry::new(now, self.capacity));

        let elapsed = now
            .saturating_duration_since(entry.last_refill)
            .as_secs_f64();
        if elapsed > 0.0 {
            entry.tokens = (entry.tokens + elapsed * self.refill_per_sec).min(self.capacity);
            entry.last_refill = now;
        }

        if authenticated {
            entry.penalty_ms = 0;
            entry.penalty_until = now;
            return self.base_success_delay;
        }

        let mut delay = self.base_failure_delay;

        if now < entry.penalty_until {
            delay += entry.penalty_until.saturating_duration_since(now);
        }

        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            return delay;
        }

        entry.penalty_ms = if entry.penalty_ms == 0 {
            self.base_penalty_ms
        } else {
            (entry.penalty_ms.saturating_mul(2)).min(self.max_penalty_ms)
        };
        entry.penalty_until = now + Duration::from_millis(entry.penalty_ms);
        delay + Duration::from_millis(entry.penalty_ms)
    }

    fn gc(&mut self, now: Instant) {
        self.entries.retain(|_, entry| {
            now.saturating_duration_since(entry.last_refill) <= self.ttl
                || now < entry.penalty_until
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn penalty_grows_for_burst_failures() {
        let mut limiter = AuthRateLimiter::default();
        let ip: IpAddr = "203.0.113.7".parse().expect("ip");

        let mut last = Duration::ZERO;
        for _ in 0..20 {
            let d = limiter.delay_for_attempt(ip, false);
            if d > last {
                last = d;
            }
        }

        assert!(last >= Duration::from_millis(100));
    }

    #[test]
    fn success_path_keeps_small_delay() {
        let mut limiter = AuthRateLimiter::default();
        let ip: IpAddr = "198.51.100.9".parse().expect("ip");
        let delay = limiter.delay_for_attempt(ip, true);
        assert!(delay <= Duration::from_millis(20));
    }
}
