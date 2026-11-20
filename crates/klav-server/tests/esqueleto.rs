//! Skeleton behaviour: health, security headers, JSON errors, rate limits.

mod common;

use common::TestServer;
use klav_proto::{ErrorBody, ErrorCode, HealthResponse};

#[tokio::test]
async fn health_reports_ok_and_version() {
    let server = TestServer::start().await;
    let res = server
        .http
        .get(server.url("/v1/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: HealthResponse = res.json().await.unwrap();
    assert_eq!(body.status, "ok");
    assert_eq!(body.version, klav_server::VERSION);
    assert_eq!(body.registration_open, Some(true));

    // Clients say registration is closed before asking for a password
    // (ADR 0028 §3).
    let closed = TestServer::start_with(|c| c.allow_registration = false).await;
    let body: HealthResponse = closed
        .http
        .get(closed.url("/v1/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body.registration_open, Some(false));
}

#[tokio::test]
async fn every_response_carries_security_headers() {
    let server = TestServer::start().await;
    for path in ["/v1/health", "/nope"] {
        let res = server.http.get(server.url(path)).send().await.unwrap();
        let h = res.headers();
        assert_eq!(h["x-content-type-options"], "nosniff", "{path}");
        assert_eq!(h["x-frame-options"], "DENY");
        assert_eq!(h["referrer-policy"], "no-referrer");
        assert_eq!(h["cache-control"], "no-store");
        assert!(
            h["strict-transport-security"]
                .to_str()
                .unwrap()
                .starts_with("max-age=")
        );
        assert!(
            h["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("default-src 'none'")
        );
    }
}

#[tokio::test]
async fn unknown_routes_return_json_404() {
    let server = TestServer::start().await;
    let res = server
        .http
        .get(server.url("/v1/nope"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    let body: ErrorBody = res.json().await.unwrap();
    assert_eq!(body.error, ErrorCode::NotFound);
}

#[tokio::test]
async fn per_ip_rate_limit_returns_429_with_retry_after() {
    let server = TestServer::start_with(|c| {
        c.rate_limit.ip_per_minute = 1;
        c.rate_limit.ip_burst = 3;
    })
    .await;
    for _ in 0..3 {
        let res = server
            .http
            .get(server.url("/v1/health"))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
    }
    let res = server
        .http
        .get(server.url("/v1/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 429);
    let retry: u64 = res.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(retry >= 1);
    let body: ErrorBody = res.json().await.unwrap();
    assert_eq!(body.error, ErrorCode::TooManyRequests);
}
