//! In-memory token-bucket rate limiting, keyed by client IP, by account and
//! (for authentication endpoints) by e-mail and IP.
//!
//! State lives in the process: with several server instances each one limits
//! independently, which is acceptable for self-hosting and for a hosted plan
//! behind sticky routing (see `docs/self-hosting.md`).
//!
//! The map of buckets has a hard size ([`MAX_BUCKETS`]): full (idle) buckets
//! are pruned now and then, and if that is not enough the least recently used
//! are dropped. Clients that rotate addresses can only make the server forget
//! old buckets, never grow it without bound.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::ApiError;
use crate::state::AppState;

/// Refill rate and bucket size.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Quota {
    pub(crate) per_minute: u32,
    pub(crate) burst: u32,
}

impl Quota {
    fn rate_per_sec(self) -> f64 {
        f64::from(self.per_minute.max(1)) / 60.0
    }

    fn size(self) -> f64 {
        f64::from(self.burst.max(1))
    }
}

struct Bucket {
    tokens: f64,
    updated: Instant,
    /// The quota it was last checked with (to know when it is full again).
    quota: Quota,
}

impl Bucket {
    fn is_full_at(&self, now: Instant) -> bool {
        let refilled = self.tokens
            + now.saturating_duration_since(self.updated).as_secs_f64() * self.quota.rate_per_sec();
        refilled >= self.quota.size()
    }
}

/// Above this many buckets, full ones are pruned (at most once per
/// [`PRUNE_EVERY`]).
const PRUNE_THRESHOLD: usize = 50_000;
/// Hard limit: when reached, the least recently used buckets are dropped
/// down to [`EVICT_TO`].
pub(crate) const MAX_BUCKETS: usize = 100_000;
const EVICT_TO: usize = MAX_BUCKETS * 9 / 10;
const PRUNE_EVERY: Duration = Duration::from_secs(1);

#[derive(Default)]
struct Buckets {
    map: HashMap<String, Bucket>,
    last_prune: Option<Instant>,
}

impl Buckets {
    /// Makes room before a new key is inserted. Pruning walks the whole map,
    /// so it runs only above [`PRUNE_THRESHOLD`] and at most once per
    /// [`PRUNE_EVERY`]; eviction leaves 10 % of headroom, so it is amortized
    /// over the next inserts.
    fn make_room(&mut self, now: Instant) {
        if self.map.len() >= PRUNE_THRESHOLD
            && self
                .last_prune
                .is_none_or(|t| now.saturating_duration_since(t) >= PRUNE_EVERY)
        {
            self.map.retain(|_, b| !b.is_full_at(now));
            self.last_prune = Some(now);
        }
        if self.map.len() >= MAX_BUCKETS {
            let mut ages: Vec<(Instant, String)> = self
                .map
                .iter()
                .map(|(k, b)| (b.updated, k.clone()))
                .collect();
            let drop = ages.len() - EVICT_TO;
            ages.select_nth_unstable_by_key(drop - 1, |(t, _)| *t);
            for (_, key) in &ages[..drop] {
                self.map.remove(key);
            }
            tracing::warn!(
                dropped = drop,
                "rate limiter full: least recently used buckets dropped"
            );
        }
    }
}

/// A set of token buckets.
#[derive(Default)]
pub(crate) struct RateLimiter {
    buckets: Mutex<Buckets>,
}

impl RateLimiter {
    /// Takes one token from the bucket `key`. On failure returns the number
    /// of seconds until a token is available.
    pub(crate) fn check(&self, key: &str, quota: Quota) -> Result<(), u64> {
        self.check_at(key, quota, Instant::now())
    }

    fn check_at(&self, key: &str, quota: Quota, now: Instant) -> Result<(), u64> {
        let rate_per_sec = quota.rate_per_sec();
        let burst = quota.size();
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !buckets.map.contains_key(key) {
            buckets.make_room(now);
        }
        let bucket = buckets.map.entry(key.to_owned()).or_insert(Bucket {
            tokens: burst,
            updated: now,
            quota,
        });
        let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate_per_sec).min(burst);
        bucket.updated = now;
        bucket.quota = quota;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            let wait = (1.0 - bucket.tokens) / rate_per_sec;
            // Truncation is fine: the value is small and positive.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            Err(wait.ceil().max(1.0) as u64)
        }
    }

    /// Whether the bucket `key` has a token now, without taking it (a
    /// bucket never used is full). For limits that charge only failures:
    /// peek first, so an empty bucket refuses before the work, and take the
    /// token with [`RateLimiter::check`] when the attempt fails.
    pub(crate) fn peek(&self, key: &str, quota: Quota) -> Result<(), u64> {
        self.peek_at(key, quota, Instant::now())
    }

    fn peek_at(&self, key: &str, quota: Quota, now: Instant) -> Result<(), u64> {
        let rate_per_sec = quota.rate_per_sec();
        let buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(bucket) = buckets.map.get(key) else {
            return Ok(());
        };
        let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
        let tokens = (bucket.tokens + elapsed * rate_per_sec).min(quota.size());
        if tokens >= 1.0 {
            Ok(())
        } else {
            let wait = (1.0 - tokens) / rate_per_sec;
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            Err(wait.ceil().max(1.0) as u64)
        }
    }

    /// Like [`RateLimiter::check`] but returns an [`ApiError`].
    pub(crate) fn enforce(&self, key: &str, quota: Quota) -> Result<(), ApiError> {
        self.check(key, quota)
            .map_err(|retry_after_secs| ApiError::TooManyRequests { retry_after_secs })
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .map
            .len()
    }
}

/// The client address as seen by the server (after the trusted proxy header
/// when configured). Inserted into request extensions by [`limit_by_ip`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClientIp(pub(crate) Option<IpAddr>);

impl ClientIp {
    /// The bucket key. IPv6 addresses are grouped by their `/64`: one
    /// subscriber usually gets a whole `/64`, so per-address buckets would
    /// let them rotate through 2^64 addresses. IPv4-mapped IPv6 addresses
    /// count as the IPv4 address.
    pub(crate) fn key(&self) -> String {
        match self.0.map(|ip| ip.to_canonical()) {
            Some(IpAddr::V4(ip)) => ip.to_string(),
            Some(IpAddr::V6(ip)) => {
                let s = ip.segments();
                format!("{}/64", Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
            None => "unknown".into(),
        }
    }
}

/// Where the client IP comes from (`Config::trust_forwarded_for` and
/// `Config::trusted_ip_header`, mutually exclusive).
#[derive(Debug, Clone, Copy)]
enum IpSource<'a> {
    /// The TCP peer (default: no header is trusted).
    Peer,
    /// The rightmost `X-Forwarded-For` entry.
    ForwardedFor,
    /// A header the proxy sets to the client address (`X-Real-IP` on
    /// Railway), replacing whatever the client sent.
    Header(&'a str),
}

fn client_ip(req: &Request, source: IpSource<'_>) -> Option<IpAddr> {
    let from_header = match source {
        IpSource::Peer => None,
        // The rightmost entry is the one added by our own reverse proxy;
        // anything to its left is client-controlled.
        IpSource::ForwardedFor => req
            .headers()
            .get_all("x-forwarded-for")
            .iter()
            .next_back()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|s| s.trim().parse::<IpAddr>().ok()),
        // The last occurrence: a proxy that appends instead of replacing
        // still puts its own value last. The whole value must be one
        // address; anything else falls back to the peer.
        IpSource::Header(name) => req
            .headers()
            .get_all(name)
            .iter()
            .next_back()
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<IpAddr>().ok()),
    };
    from_header.or_else(|| {
        req.extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip())
    })
}

/// Middleware: per-IP limit on every request.
pub(crate) async fn limit_by_ip(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let config = state.config();
    let source = match (&config.trusted_ip_header, config.trust_forwarded_for) {
        (Some(name), _) => IpSource::Header(name),
        (None, true) => IpSource::ForwardedFor,
        (None, false) => IpSource::Peer,
    };
    let ip = ClientIp(client_ip(&req, source));
    let quota = Quota {
        per_minute: config.rate_limit.ip_per_minute,
        burst: config.rate_limit.ip_burst,
    };
    if let Err(e) = state.limiter().enforce(&format!("ip:{}", ip.key()), quota) {
        return e.into_response();
    }
    req.extensions_mut().insert(ip);
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peeking_takes_no_token() {
        let limiter = RateLimiter::default();
        let quota = Quota {
            per_minute: 1,
            burst: 2,
        };
        let t0 = Instant::now();
        // An unknown bucket is full, and peeking does not create it.
        assert!(limiter.peek_at("k", quota, t0).is_ok());
        assert_eq!(limiter.len(), 0);
        assert!(limiter.check_at("k", quota, t0).is_ok());
        for _ in 0..5 {
            assert!(limiter.peek_at("k", quota, t0).is_ok());
        }
        assert!(limiter.check_at("k", quota, t0).is_ok());
        // Empty now: peek refuses with the wait, and refills with time.
        assert_eq!(limiter.peek_at("k", quota, t0), Err(60));
        assert!(
            limiter
                .peek_at("k", quota, t0 + Duration::from_secs(60))
                .is_ok()
        );
    }

    const QUOTA: Quota = Quota {
        per_minute: 60,
        burst: 3,
    };

    #[test]
    fn bucket_drains_and_refills() {
        let limiter = RateLimiter::default();
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(limiter.check_at("k", QUOTA, t0).is_ok());
        }
        assert_eq!(limiter.check_at("k", QUOTA, t0), Err(1));
        // Other keys are independent.
        assert!(limiter.check_at("other", QUOTA, t0).is_ok());
        // One token per second.
        assert!(
            limiter
                .check_at("k", QUOTA, t0 + Duration::from_millis(1001))
                .is_ok()
        );
        assert!(
            limiter
                .check_at("k", QUOTA, t0 + Duration::from_millis(1002))
                .is_err()
        );
    }

    #[test]
    fn the_map_never_grows_past_its_hard_limit() {
        let limiter = RateLimiter::default();
        let t0 = Instant::now();
        // Every bucket stays drained (never full again within the test), so
        // pruning cannot help: only eviction keeps the map bounded.
        let slow = Quota {
            per_minute: 1,
            burst: 1,
        };
        for i in 0..(MAX_BUCKETS + 5_000) {
            let _ = limiter.check_at(&format!("k{i}"), slow, t0);
            assert!(limiter.len() <= MAX_BUCKETS);
        }
        // The most recent client keeps its (drained) bucket.
        let last = format!("k{}", MAX_BUCKETS + 4_999);
        assert!(limiter.check_at(&last, slow, t0).is_err());
    }

    #[test]
    fn full_buckets_are_pruned_with_their_own_quota() {
        let limiter = RateLimiter::default();
        let t0 = Instant::now();
        let fast = Quota {
            per_minute: 6_000,
            burst: 1,
        };
        for i in 0..PRUNE_THRESHOLD {
            let _ = limiter.check_at(&format!("k{i}"), fast, t0);
        }
        // A second later they are all full again and go on the next insert.
        let _ = limiter.check_at("new", QUOTA, t0 + Duration::from_secs(1));
        assert_eq!(limiter.len(), 1);
    }

    fn request(headers: &[(&str, &str)]) -> Request {
        let mut builder = Request::builder();
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let mut req = builder.body(axum::body::Body::empty()).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 1], 443))));
        req
    }

    #[test]
    fn forwarded_for_uses_rightmost_entry_only_when_trusted() {
        let req = request(&[("x-forwarded-for", "1.1.1.1, 2.2.2.2")]);
        let peer: Option<IpAddr> = "10.0.0.1".parse().ok();
        assert_eq!(client_ip(&req, IpSource::Peer), peer);
        assert_eq!(
            client_ip(&req, IpSource::ForwardedFor),
            "2.2.2.2".parse().ok()
        );
    }

    #[test]
    fn a_trusted_header_is_used_only_when_configured() {
        let peer: Option<IpAddr> = "10.0.0.1".parse().ok();
        let req = request(&[("x-real-ip", "203.0.113.7")]);
        assert_eq!(
            client_ip(&req, IpSource::Peer),
            peer,
            "not trusted by default"
        );
        assert_eq!(
            client_ip(&req, IpSource::ForwardedFor),
            peer,
            "x-forwarded-for trust does not extend to other headers"
        );
        assert_eq!(
            client_ip(&req, IpSource::Header("x-real-ip")),
            "203.0.113.7".parse().ok()
        );
        // Two values: the last one (the proxy's) wins.
        let req = request(&[("x-real-ip", "1.1.1.1"), ("x-real-ip", "203.0.113.7")]);
        assert_eq!(
            client_ip(&req, IpSource::Header("x-real-ip")),
            "203.0.113.7".parse().ok()
        );
        // Missing or not a single address: the peer.
        for bad in ["", "1.1.1.1, 2.2.2.2", "nope"] {
            let req = request(&[("x-real-ip", bad)]);
            assert_eq!(
                client_ip(&req, IpSource::Header("x-real-ip")),
                peer,
                "{bad}"
            );
        }
        assert_eq!(
            client_ip(&request(&[]), IpSource::Header("x-real-ip")),
            peer
        );
    }

    #[test]
    fn ipv6_clients_share_a_bucket_per_64() {
        let key = |s: &str| ClientIp(s.parse().ok()).key();
        assert_eq!(key("2001:db8:1:2:aaaa::1"), key("2001:db8:1:2:ffff::9"));
        assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));
        assert_eq!(key("2001:db8:1:2::1"), "2001:db8:1:2::/64");
        assert_eq!(key("::ffff:192.0.2.1"), "192.0.2.1");
        assert_eq!(key("192.0.2.1"), "192.0.2.1");
        assert_eq!(ClientIp(None).key(), "unknown");
    }
}
