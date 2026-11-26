//! Per-account quotas, enforced inside the enclave (ADR 0051 §3.3): the
//! parent sees only SNI and bytes, so it cannot attribute traffic to an
//! account.
//!
//! | Quota | Where | On excess |
//! |---|---|---|
//! | Live sandboxes (10) | [`crate::proxy::ProxyState::with_account_live_cap`] | `429 klav_rate_limited` on start |
//! | Requests per minute (120) | [`enforce`] | `429 klav_rate_limited` with `retry_after` |
//! | Request body (32 MiB) | [`enforce`] and the state's body limit | `413 klav_upstream_blocked` |
//! | Egress bytes per day (2 GiB, up and down) | [`enforce`] | `429 klav_rate_limited` until the day rolls |
//! | Concurrent SSE streams (8, each ≤ 1 h) | [`enforce`] | the oldest stream closes |
//! | Concurrent upstream calls | the state's own in-flight cap ([`crate::proxy::MAX_IN_FLIGHT`]) | `429 klav_rate_limited` |
//!
//! Only calls to a profile count toward the rate, the body and the egress;
//! the channel's own routes (`/_klav/…`) do not.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use futures_util::StreamExt as _;
use tokio::sync::oneshot;

use super::refuse;

const DAY: Duration = Duration::from_secs(24 * 60 * 60);
const MINUTE: Duration = Duration::from_secs(60);

/// The limits of one account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaLimits {
    /// Live sandboxes, whatever their issuer.
    pub live_sandboxes: usize,
    /// Calls to a profile per minute.
    pub requests_per_minute: u32,
    /// Largest request body.
    pub max_body: usize,
    /// Bytes up and down per day.
    pub egress_bytes_per_day: u64,
    /// Open SSE streams.
    pub sse_streams: usize,
    /// Longest an SSE stream stays open.
    pub sse_max: Duration,
}

impl Default for QuotaLimits {
    fn default() -> Self {
        Self {
            live_sandboxes: 10,
            requests_per_minute: 120,
            max_body: 32 * 1024 * 1024,
            egress_bytes_per_day: 2 * 1024 * 1024 * 1024,
            sse_streams: 8,
            sse_max: Duration::from_secs(60 * 60),
        }
    }
}

/// The counters of one account.
pub struct Quotas {
    limits: QuotaLimits,
    rate: Mutex<(Instant, u32)>,
    egress: Mutex<(Instant, u64)>,
    streams: Mutex<VecDeque<(u64, oneshot::Sender<()>)>>,
    next_stream: std::sync::atomic::AtomicU64,
}

impl Quotas {
    /// Fresh counters under `limits`.
    pub fn new(limits: QuotaLimits) -> Self {
        let now = Instant::now();
        Self {
            limits,
            rate: Mutex::new((now, 0)),
            egress: Mutex::new((now, 0)),
            streams: Mutex::new(VecDeque::new()),
            next_stream: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// The limits.
    pub fn limits(&self) -> &QuotaLimits {
        &self.limits
    }

    /// Counts a call against the minute's rate; the seconds to wait if it
    /// is over.
    fn admit_call(&self, now: Instant) -> Result<(), u64> {
        let mut rate = self
            .rate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if now.duration_since(rate.0) >= MINUTE {
            *rate = (now, 0);
        }
        if rate.1 >= self.limits.requests_per_minute {
            let left = MINUTE.saturating_sub(now.duration_since(rate.0));
            return Err(left.as_secs().max(1));
        }
        rate.1 += 1;
        Ok(())
    }

    /// Whether the day's egress has room; the seconds until it rolls if
    /// not.
    fn egress_left(&self, now: Instant) -> Result<(), u64> {
        let mut egress = self
            .egress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if now.duration_since(egress.0) >= DAY {
            *egress = (now, 0);
        }
        if egress.1 >= self.limits.egress_bytes_per_day {
            let left = DAY.saturating_sub(now.duration_since(egress.0));
            return Err(left.as_secs().max(1));
        }
        Ok(())
    }

    /// Counts `n` bytes of egress.
    pub fn count_egress(&self, n: usize) {
        let mut egress = self
            .egress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        egress.1 = egress.1.saturating_add(n as u64);
    }

    /// The bytes counted today.
    pub fn egress_today(&self) -> u64 {
        self.egress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .1
    }

    /// Opens a stream slot, closing the oldest open stream when every slot
    /// is taken. The receiver fires when this stream must close.
    fn open_stream(self: &Arc<Self>) -> (StreamSlot, oneshot::Receiver<()>) {
        let id = self
            .next_stream
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        let mut streams = self
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while streams.len() >= self.limits.sse_streams.max(1) {
            if let Some((_, oldest)) = streams.pop_front() {
                let _ = oldest.send(());
            }
        }
        streams.push_back((id, tx));
        (
            StreamSlot {
                quotas: Arc::clone(self),
                id,
            },
            rx,
        )
    }

    /// Open SSE streams.
    pub fn open_streams(&self) -> usize {
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

/// A stream's place among the open ones; gives it back when dropped.
struct StreamSlot {
    quotas: Arc<Quotas>,
    id: u64,
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        self.quotas
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(id, _)| *id != self.id);
    }
}

/// A body whose bytes count toward the day's egress; past `cap` bytes it
/// ends with an error.
fn counted(body: Body, quotas: Arc<Quotas>, cap: Option<usize>) -> Body {
    let mut seen = 0usize;
    Body::from_stream(body.into_data_stream().map(move |chunk| {
        let chunk = chunk?;
        seen = seen.saturating_add(chunk.len());
        quotas.count_egress(chunk.len());
        if cap.is_some_and(|cap| seen > cap) {
            return Err(axum::Error::new(
                "the request body is over the account's limit",
            ));
        }
        Ok(chunk)
    }))
}

/// Whether a path is a call to a profile (not one of the channel's routes).
fn is_call(path: &str) -> bool {
    !path.starts_with("/_klav/")
}

/// The middleware on an account's channel routes.
pub async fn enforce(State(quotas): State<Arc<Quotas>>, req: Request, next: Next) -> Response {
    let now = Instant::now();
    let call = is_call(req.uri().path());
    if call {
        if let Some(len) = req
            .headers()
            .get(axum::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            && len > quotas.limits.max_body as u64
        {
            return refuse(
                StatusCode::PAYLOAD_TOO_LARGE,
                "klav_upstream_blocked",
                "This request's body is larger than Klav Cloud's proxy takes for this account.",
                "Send a smaller body. Do not retry the same request.",
                None,
            );
        }
        if let Err(retry_after) = quotas.egress_left(now) {
            return refuse(
                StatusCode::TOO_MANY_REQUESTS,
                "klav_rate_limited",
                "This account used its traffic for today through Klav Cloud's proxy.",
                "Wait until retry_after seconds have passed, then retry.",
                Some(retry_after),
            );
        }
        if let Err(retry_after) = quotas.admit_call(now) {
            return refuse(
                StatusCode::TOO_MANY_REQUESTS,
                "klav_rate_limited",
                "Too many calls this minute for this account through Klav Cloud's proxy.",
                "Wait retry_after seconds, then retry.",
                Some(retry_after),
            );
        }
    }
    let cap = call.then_some(quotas.limits.max_body);
    let req = req.map(|body| {
        if call {
            counted(body, Arc::clone(&quotas), cap)
        } else {
            body
        }
    });
    let res = next.run(req).await;
    if !call {
        return res;
    }
    let stream = res
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("text/event-stream"));
    let sse_max = quotas.limits.sse_max;
    res.map(|body| {
        let body = counted(body, Arc::clone(&quotas), None);
        if !stream {
            return body;
        }
        let (slot, closed) = quotas.open_stream();
        let end = async move {
            tokio::select! {
                _ = closed => {}
                () = tokio::time::sleep(sse_max) => {}
            }
        };
        Body::from_stream(body.into_data_stream().take_until(end).map(move |chunk| {
            // The slot lives as long as the stream.
            let _ = &slot;
            chunk
        }))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> QuotaLimits {
        QuotaLimits {
            live_sandboxes: 2,
            requests_per_minute: 3,
            max_body: 10,
            egress_bytes_per_day: 100,
            sse_streams: 2,
            sse_max: Duration::from_secs(5),
        }
    }

    #[test]
    fn the_rate_rolls_each_minute() {
        let q = Quotas::new(limits());
        let now = Instant::now();
        for _ in 0..3 {
            assert_eq!(q.admit_call(now), Ok(()));
        }
        let retry = q.admit_call(now).expect_err("over");
        assert!((1..=60).contains(&retry));
        assert_eq!(q.admit_call(now + MINUTE), Ok(()));
    }

    #[test]
    fn egress_counts_until_the_day_rolls() {
        let q = Quotas::new(limits());
        let now = Instant::now();
        q.count_egress(99);
        assert_eq!(q.egress_left(now), Ok(()));
        q.count_egress(1);
        assert!(q.egress_left(now).is_err());
        assert_eq!(q.egress_left(now + DAY), Ok(()));
        assert_eq!(q.egress_today(), 0);
    }

    #[tokio::test]
    async fn a_new_stream_over_the_cap_closes_the_oldest() {
        let q = Arc::new(Quotas::new(limits()));
        let (first, mut first_closed) = q.open_stream();
        let (_second, mut second_closed) = q.open_stream();
        assert_eq!(q.open_streams(), 2);
        let (_third, _) = q.open_stream();
        assert_eq!(q.open_streams(), 2);
        assert!(first_closed.try_recv().is_ok(), "the oldest closes");
        assert!(second_closed.try_recv().is_err());
        drop(first);
        assert_eq!(q.open_streams(), 2);
    }
}
