//! The most calls per minute through each profile (ADR 0036 §8), counted
//! before the Klav server is asked, so a flood never reaches the audit
//! log. A sliding window of the last 60 seconds, in memory: a restart
//! starts it again.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);

/// Calls in the last minute, by profile.
#[derive(Default)]
pub struct RateLimits {
    calls: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimits {
    /// Counts a call through `profile` at `now` if it fits in `per_minute`;
    /// otherwise how many seconds until one does.
    pub fn check(&self, profile: &str, per_minute: u32, now: Instant) -> Result<(), u64> {
        let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
        let seen = calls.entry(profile.to_owned()).or_default();
        while seen
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= WINDOW)
        {
            seen.pop_front();
        }
        if seen.len() >= per_minute as usize {
            let oldest = seen.front().copied().unwrap_or(now);
            let wait = WINDOW.saturating_sub(now.saturating_duration_since(oldest));
            return Err(wait.as_secs().max(1));
        }
        seen.push_back(now);
        Ok(())
    }

    /// Counts a call against every `(key, per_minute)` only if it fits in
    /// all of them; otherwise charges none and says how many seconds until
    /// it fits in the fullest.
    pub fn check_all(&self, limits: &[(String, u32)], now: Instant) -> Result<(), u64> {
        let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
        // Forget every key with no call in the window (an ended sandbox's
        // among them), so the map only holds what is in use.
        calls.retain(|_, seen| {
            seen.back()
                .is_some_and(|t| now.saturating_duration_since(*t) < WINDOW)
        });
        let mut wait = 0;
        for (key, per_minute) in limits {
            let seen = calls.entry(key.clone()).or_default();
            while seen
                .front()
                .is_some_and(|t| now.saturating_duration_since(*t) >= WINDOW)
            {
                seen.pop_front();
            }
            if seen.len() >= *per_minute as usize {
                let oldest = seen.front().copied().unwrap_or(now);
                let left = WINDOW.saturating_sub(now.saturating_duration_since(oldest));
                wait = wait.max(left.as_secs().max(1));
            }
        }
        if wait > 0 {
            return Err(wait);
        }
        for (key, _) in limits {
            calls.entry(key.clone()).or_default().push_back(now);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_profile_gets_its_rate_and_no_more() {
        let limits = RateLimits::default();
        let t0 = Instant::now();
        for i in 0..3 {
            assert!(limits.check("a", 3, t0 + Duration::from_secs(i)).is_ok());
        }
        let wait = limits
            .check("a", 3, t0 + Duration::from_secs(10))
            .unwrap_err();
        assert_eq!(wait, 50);
        // Another profile counts on its own.
        assert!(limits.check("b", 3, t0 + Duration::from_secs(10)).is_ok());
        // A minute after the first call, one fits again.
        assert!(limits.check("a", 3, t0 + Duration::from_secs(60)).is_ok());
        assert!(limits.check("a", 3, t0 + Duration::from_secs(60)).is_err());
    }

    /// Review of #306, F4: a sandbox over its own rate never spends the
    /// profile's, which other callers share.
    #[test]
    fn a_call_over_one_limit_charges_none() {
        let limits = RateLimits::default();
        let t0 = Instant::now();
        let both = |k: &str| vec![("p".to_owned(), 5), (k.to_owned(), 2)];
        assert!(limits.check_all(&both("sandbox:a"), t0).is_ok());
        assert!(limits.check_all(&both("sandbox:a"), t0).is_ok());
        for _ in 0..10 {
            assert!(limits.check_all(&both("sandbox:a"), t0).is_err());
        }
        // The profile still has its other 3 calls for everyone else.
        let profile = [("p".to_owned(), 5)];
        for _ in 0..3 {
            assert!(limits.check_all(&profile, t0).is_ok());
        }
        assert!(limits.check_all(&profile, t0).is_err());
    }
}
