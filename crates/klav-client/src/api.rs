//! HTTP transport (also used by `klav-sdk` for signed agent requests). Bodies are `klav-proto` types; nothing here sees a
//! plaintext secret (only OPAQUE messages, ciphertext and session tokens).

use std::time::Duration;

use klav_proto::{ErrorBody, ErrorCode};
use reqwest::{Method, Response, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{ClientError, ClientResult};
use crate::url::ServerUrl;

/// Largest JSON response read from a server (a whole vault's `changes`
/// fits with room to spare). A hostile server cannot make the client run
/// out of memory with an endless body (ADR 0030, layer 10).
pub const MAX_JSON_RESPONSE: usize = 128 * 1024 * 1024;
/// Largest error body read.
const MAX_ERROR_RESPONSE: usize = 64 * 1024;

/// A client for one server.
#[derive(Clone)]
pub(crate) struct Api {
    http: reqwest::Client,
    base: ServerUrl,
}

/// How long a kept-alive connection may sit unused before a request opens
/// a new one instead. An app's runtime runs only inside a call (`KlavCore`),
/// so nothing notices a server or an edge closing an idle connection until
/// the next request is written into it, and that request fails ("error
/// sending request"). A connection unused for longer is not reused, so a
/// call this long after the last one does not meet one closed meanwhile.
/// The pool counts with a clock that stops while the device sleeps: after a
/// sleep a connection may be reused although more time than this passed.
/// That, and a connection closed sooner (by an edge, a server restart), is
/// what the client for a Klav server retries a GET for. The cost is one
/// more TLS handshake for calls spaced further apart.
pub const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(15);

/// How long opening a connection may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a whole request may take, a retried GET's two attempts
/// included: reqwest checks it around the retry, not inside it.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// The HTTP client every Klav client uses: rustls with the platform
/// verifier (ADR 0011), timeouts, and no redirects (they could carry
/// credentials elsewhere). It sends nothing twice that a server may have
/// read (hyper only resends a request it never wrote to a reused
/// connection); the client for one Klav server adds a retry for GETs.
pub fn http_client() -> ClientResult<reqwest::Client> {
    builder()
        .build()
        .map_err(|e| ClientError::Network(e.to_string()))
}

/// A client for another service than the Klav server (Klav Cloud's
/// proxy's public API, ADR 0051 §6.4): same TLS and redirect policy, no
/// retry, and `timeout` for the whole request.
#[cfg(feature = "hosted-proxy")]
pub(crate) fn plain_client(timeout: Duration) -> ClientResult<reqwest::Client> {
    builder()
        .timeout(timeout)
        .build()
        .map_err(|e| ClientError::Network(e.to_string()))
}

fn builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .user_agent(concat!("klav/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .pool_idle_timeout(IDLE_CONNECTION_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
}

/// The retry of a client for the Klav server at `host`: a GET whose
/// connection closed before an answer came is sent once more, on another
/// connection; nothing else is ever sent twice. Within the whole request's
/// [`REQUEST_TIMEOUT`], so a retried GET still takes at most 60 s; a
/// failure to connect (bounded by [`CONNECT_TIMEOUT`]) is not retried.
///
/// Only the person's requests (bearer tokens) go through here. An agent's
/// requests are signed with a nonce the server spends on the first copy it
/// reads (`klav-sdk`), so they use [`http_client`] and are never repeated.
fn retry_closed_gets(host: &str) -> reqwest::retry::Builder {
    reqwest::retry::for_host(host.to_owned())
        .max_retries_per_request(1)
        .classify_fn(|attempt| {
            if attempt.method() == Method::GET
                && attempt.error().is_some_and(closed_before_an_answer)
            {
                attempt.retryable()
            } else {
                attempt.success()
            }
        })
}

/// Whether a request failed because its connection closed before a whole
/// answer's head arrived: the server or an edge closed it while it sat in
/// the pool, or reset it. Never a failure to connect, a timeout, or an
/// answer of any status (those are not errors here).
fn closed_before_an_answer(error: &(dyn std::error::Error + 'static)) -> bool {
    if let Some(e) = error.downcast_ref::<reqwest::Error>()
        && (e.is_connect() || e.is_timeout())
    {
        return false;
    }
    let mut source = Some(error);
    while let Some(e) = source {
        if let Some(io) = e.downcast_ref::<std::io::Error>()
            && matches!(
                io.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    // TLS: the peer closed without a `close_notify`.
                    | std::io::ErrorKind::UnexpectedEof
            )
        {
            return true;
        }
        // hyper's `IncompleteMessage`, which klav-client cannot name
        // without depending on hyper; the tests pin the text.
        if e.to_string() == "connection closed before message completed" {
            return true;
        }
        source = e.source();
    }
    false
}

impl Api {
    pub(crate) fn new(base: ServerUrl) -> ClientResult<Self> {
        let http = builder()
            .retry(retry_closed_gets(base.host()))
            .build()
            .map_err(|e| ClientError::Network(e.to_string()))?;
        Ok(Self { http, base })
    }

    pub(crate) fn base(&self) -> &ServerUrl {
        &self.base
    }

    /// Sends a request and returns the raw response (any status).
    pub(crate) async fn send<B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&B>,
    ) -> ClientResult<Response> {
        let mut req = self.http.request(method, self.base.join(path));
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        if let Some(body) = body {
            req = req.json(body);
        }
        req.send()
            .await
            .map_err(|e| ClientError::Network(without_url(&e)))
    }

    /// Sends a request with a prepared [`Body`].
    pub(crate) async fn send_body(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: &Body<'_>,
    ) -> ClientResult<Response> {
        let mut req = self.http.request(method, self.base.join(path));
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        match body {
            Body::Empty => {}
            Body::Json(bytes) => {
                req = req
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(bytes.clone());
            }
            Body::Bytes(bytes) => {
                req = req
                    .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                    .body(bytes.to_vec());
            }
        }
        req.send()
            .await
            .map_err(|e| ClientError::Network(without_url(&e)))
    }

    /// Unauthenticated JSON request that must succeed.
    pub(crate) async fn call<B: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: &B,
    ) -> ClientResult<R> {
        let res = self.send(method, path, None, Some(body)).await?;
        json(res).await
    }
}

/// A request body, prepared once so it can be resent after a refresh.
pub(crate) enum Body<'a> {
    Empty,
    /// Serialised JSON (only ciphertext and identifiers, never plaintext).
    Json(Vec<u8>),
    /// Raw bytes (attachment ciphertext).
    Bytes(&'a [u8]),
}

impl Body<'_> {
    pub(crate) fn json(value: &(impl Serialize + ?Sized)) -> ClientResult<Self> {
        serde_json::to_vec(value)
            .map(Body::Json)
            .map_err(|e| ClientError::Invalid(format!("request body: {e}")))
    }
}

/// Network errors without the URL (it may contain IDs, never secrets, but
/// keeps messages short).
pub fn without_url(e: &reqwest::Error) -> String {
    let mut msg = e.to_string();
    if let Some(url) = e.url() {
        msg = msg.replace(url.as_str(), "");
    }
    if e.is_connect() {
        return format!("connection failed ({})", msg.trim());
    }
    msg.trim().to_owned()
}

/// Decodes a successful JSON response, or turns an error response into a
/// [`ClientError`].
pub async fn json<R: DeserializeOwned>(res: Response) -> ClientResult<R> {
    if !res.status().is_success() {
        return Err(error(res).await);
    }
    let bytes = read_limited(res, MAX_JSON_RESPONSE).await?;
    serde_json::from_slice(&bytes)
        .map_err(|e| ClientError::Network(format!("invalid response: {e}")))
}

/// Reads a whole body, refusing one longer than `limit` bytes (by its
/// `Content-Length` before reading, and while reading).
pub async fn read_limited(mut res: Response, limit: usize) -> ClientResult<Vec<u8>> {
    let too_big = || {
        ClientError::Network(format!(
            "the server's response is larger than {} KiB",
            limit / 1024
        ))
    };
    if res.content_length().is_some_and(|n| n > limit as u64) {
        return Err(too_big());
    }
    let mut out = Vec::new();
    while let Some(chunk) = res
        .chunk()
        .await
        .map_err(|e| ClientError::Network(format!("invalid response: {}", without_url(&e))))?
    {
        if out.len() + chunk.len() > limit {
            return Err(too_big());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Checks that a response without body succeeded.
pub async fn empty(res: Response) -> ClientResult<()> {
    if res.status().is_success() {
        Ok(())
    } else {
        Err(error(res).await)
    }
}

/// Maps an error response.
pub async fn error(res: Response) -> ClientError {
    let status = res.status();
    let body: Option<ErrorBody> = read_limited(res, MAX_ERROR_RESPONSE)
        .await
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    if status == StatusCode::CONFLICT
        && let Some(v) = body.as_ref().and_then(|b| b.current_version)
    {
        return ClientError::Conflict(v);
    }
    if status == StatusCode::CONFLICT
        && let Some(at) = body.as_ref().and_then(|b| b.last_at)
    {
        return ClientError::LaterPause(at);
    }
    // A pause (ADR 0033 §7.4). An older client, which does not know the
    // code, fails to read the body and gets a plain 403 below.
    if let Some(b) = body.as_ref()
        && b.error == ErrorCode::AgentsPaused
    {
        return ClientError::Paused(b.paused);
    }
    // The person asked to delete the account (ADR 0037 §3): every agent
    // stops, with when it happens.
    if let Some(b) = body.as_ref()
        && b.error == ErrorCode::AccountDeleting
    {
        return ClientError::AccountDeleting(b.delete_at);
    }
    // An invite that cannot be used (ADR 0048 §1.3), by its code and not
    // its status: a `429` or `404` from the same route is not one.
    if let Some(b) = body.as_ref()
        && b.error == ErrorCode::InviteInvalid
    {
        return ClientError::InviteInvalid;
    }
    // Over a quota (ADR 0048 §3.2): the server's message says which, as
    // it came.
    if let Some(b) = body.as_ref()
        && b.error == ErrorCode::QuotaExceeded
    {
        return ClientError::QuotaExceeded(b.message.clone());
    }
    // A wrong master password to delete the account (ADR 0037 §1): never a
    // `401`, which would read as the end of the session.
    if let Some(b) = body.as_ref()
        && b.error == ErrorCode::ReauthFailed
    {
        return ClientError::WrongCredentials;
    }
    ClientError::Api {
        status: status.as_u16(),
        code: body.as_ref().map(|b| b.error),
        message: body.map_or_else(
            || status.canonical_reason().unwrap_or("error").to_owned(),
            |b| b.message,
        ),
        current_version: None,
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// A one-shot HTTP server that answers `head` and then `body_len`
    /// bytes of `x`.
    async fn serve(head: String, body_len: usize) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf).await;
            let _ = s.write_all(head.as_bytes()).await;
            let chunk = vec![b'x'; 64 * 1024];
            let mut left = body_len;
            while left > 0 {
                let n = left.min(chunk.len());
                if s.write_all(&chunk[..n]).await.is_err() {
                    return;
                }
                left -= n;
            }
        });
        format!("http://{addr}/")
    }

    async fn get(url: &str) -> Response {
        http_client().unwrap().get(url).send().await.unwrap()
    }

    #[tokio::test]
    async fn bodies_beyond_the_limit_are_refused() {
        // Announced too big: refused before reading.
        let url = serve(
            "HTTP/1.1 200 OK\r\ncontent-length: 1000000000\r\n\r\n".into(),
            0,
        )
        .await;
        assert!(read_limited(get(&url).await, 1024).await.is_err());
        // Without a length (closed connection): cut while reading.
        let url = serve(
            "HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n".into(),
            256 * 1024,
        )
        .await;
        let err = read_limited(get(&url).await, 1024).await.unwrap_err();
        assert!(err.to_string().contains("larger than"), "{err}");
        // Within the limit: read whole.
        let url = serve("HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n".into(), 10).await;
        assert_eq!(read_limited(get(&url).await, 1024).await.unwrap().len(), 10);
    }

    /// An error answer with `body`.
    async fn answer(status: &str, body: &str) -> Response {
        let head = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        );
        get(&serve(head, 0).await).await
    }

    #[tokio::test]
    async fn invite_and_quota_errors_are_read_by_their_code() {
        let invalid = answer(
            "403 Forbidden",
            r#"{"error":"invite_invalid","message":"This invite code isn't valid for this email"}"#,
        )
        .await;
        assert!(matches!(error(invalid).await, ClientError::InviteInvalid));

        let msg = "Attachments for this account are limited to 250 MiB (248.3 MiB used). Delete some, or empty the trash.";
        let quota = answer(
            "403 Forbidden",
            &format!(r#"{{"error":"quota_exceeded","message":"{msg}"}}"#),
        )
        .await;
        let e = error(quota).await;
        assert!(
            matches!(&e, ClientError::QuotaExceeded(m) if m == msg),
            "{e:?}"
        );
        // Shown as it came, with nothing around it.
        assert_eq!(e.to_string(), msg);

        // The status alone says nothing: a plain 403 or a 429 from the
        // same route is not an invalid invite.
        let forbidden = answer(
            "403 Forbidden",
            r#"{"error":"forbidden","message":"forbidden"}"#,
        )
        .await;
        assert!(matches!(
            error(forbidden).await,
            ClientError::Api { status: 403, .. }
        ));
        let limited = answer(
            "429 Too Many Requests",
            r#"{"error":"too_many_requests","message":"slow down"}"#,
        )
        .await;
        assert!(matches!(
            error(limited).await,
            ClientError::Api { status: 429, .. }
        ));
    }

    /// What a [`Closer`] does with each request it reads.
    #[derive(Clone, Copy)]
    enum Then {
        /// Answers `200` and closes the connection a moment later: a server
        /// or an edge closing a kept-alive connection the client's pool
        /// holds.
        AnswerAndClose,
        /// Answers `200` and resets the connection a moment later.
        AnswerAndReset,
        /// Closes the connection without answering.
        CloseUnanswered,
        /// Answers `503` and keeps the connection.
        Unavailable,
        /// Never answers.
        Hold,
    }

    /// A server on loopback that counts the requests it reads.
    struct Closer {
        api: Api,
        requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Closer {
        fn start(then: Then) -> Self {
            use std::io::{Read, Write};
            use std::sync::atomic::Ordering;

            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counted = requests.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { return };
                    let counted = counted.clone();
                    std::thread::spawn(move || {
                        loop {
                            // Every request here has an empty body: the
                            // head is the whole request.
                            let mut head = Vec::new();
                            let mut byte = [0u8; 1];
                            while !head.ends_with(b"\r\n\r\n") {
                                match stream.read(&mut byte) {
                                    Ok(1) => head.push(byte[0]),
                                    _ => return,
                                }
                            }
                            counted.fetch_add(1, Ordering::SeqCst);
                            let ok = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";
                            match then {
                                Then::AnswerAndClose => {
                                    let _ = stream.write_all(ok);
                                    // After the client's call returned, so
                                    // the connection went back to its pool.
                                    std::thread::sleep(Duration::from_millis(100));
                                    let _ = stream.shutdown(std::net::Shutdown::Both);
                                    return;
                                }
                                Then::AnswerAndReset => {
                                    let _ = stream.write_all(ok);
                                    std::thread::sleep(Duration::from_millis(100));
                                    reset(stream);
                                    return;
                                }
                                Then::CloseUnanswered => {
                                    let _ = stream.shutdown(std::net::Shutdown::Both);
                                    return;
                                }
                                Then::Unavailable => {
                                    let _ = stream.write_all(
                                        b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n",
                                    );
                                }
                                Then::Hold => {
                                    // Until the client gives up and closes.
                                    let _ = stream.read(&mut byte);
                                    return;
                                }
                            }
                        }
                    });
                }
            });
            Self {
                api: Api::new(ServerUrl::parse(&url).unwrap()).unwrap(),
                requests,
            }
        }

        fn requests(&self) -> usize {
            self.requests.load(std::sync::atomic::Ordering::SeqCst)
        }

        async fn get(&self) -> ClientResult<String> {
            let res = self
                .api
                .send::<()>(Method::GET, "/v1/sync", None, None)
                .await?;
            res.text()
                .await
                .map_err(|e| ClientError::Network(without_url(&e)))
        }
    }

    /// Closes `stream` with a reset instead of a FIN.
    fn reset(stream: std::net::TcpStream) {
        let rt = runtime();
        rt.block_on(async {
            stream.set_nonblocking(true).unwrap();
            let stream = tokio::net::TcpStream::from_std(stream).unwrap();
            stream.set_zero_linger().unwrap();
            drop(stream);
        });
    }

    /// A runtime like `KlavCore`'s: one thread, running only inside a call.
    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// A GET inside [`IDLE_CONNECTION_TIMEOUT`] of the last call, on a
    /// kept-alive connection the server closed meanwhile while the runtime
    /// ran nothing, goes through on a new connection.
    #[test]
    fn a_get_on_a_connection_the_server_closed_goes_through() {
        let server = Closer::start(Then::AnswerAndClose);
        let rt = runtime();
        assert_eq!(rt.block_on(server.get()).unwrap(), "ok");
        // The close reaches this side while nothing runs, well inside the
        // pool's idle timeout.
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(rt.block_on(server.get()).unwrap(), "ok", "the next GET");
        assert_eq!(server.requests(), 2);
    }

    /// The same with a connection reset instead of closed.
    #[test]
    fn a_get_on_a_connection_the_server_reset_goes_through() {
        let server = Closer::start(Then::AnswerAndReset);
        let rt = runtime();
        assert_eq!(rt.block_on(server.get()).unwrap(), "ok");
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(rt.block_on(server.get()).unwrap(), "ok", "the next GET");
        assert_eq!(server.requests(), 2);
    }

    /// Two kept-alive connections, both closed meanwhile. The first attempt
    /// takes one dead connection; while it runs, the runtime also sees the
    /// other close, so the retry opens a new one. Pinned here, so a change
    /// in reqwest or hyper that hands the retry the second dead connection
    /// shows.
    #[test]
    fn a_get_with_two_closed_connections_in_the_pool() {
        let server = Closer::start(Then::AnswerAndClose);
        let rt = runtime();
        let (a, b) = rt.block_on(async { tokio::join!(server.get(), server.get()) });
        assert_eq!((a.unwrap(), b.unwrap()), ("ok".into(), "ok".into()));
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(rt.block_on(server.get()).unwrap(), "ok", "the next GET");
        assert_eq!(server.requests(), 3);
    }

    /// A GET whose connection closes before an answer is sent twice, never
    /// more.
    #[test]
    fn a_get_is_sent_at_most_twice() {
        let server = Closer::start(Then::CloseUnanswered);
        let rt = runtime();
        assert!(rt.block_on(server.get()).is_err());
        assert_eq!(server.requests(), 2);
    }

    /// A write is never repeated, whatever happened to its connection: the
    /// server may have acted on it.
    #[test]
    fn writes_are_never_repeated() {
        let rt = runtime();
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            let server = Closer::start(Then::CloseUnanswered);
            let sent = rt.block_on(server.api.send_body(
                method.clone(),
                "/v1/sync",
                None,
                &Body::Empty,
            ));
            assert!(sent.is_err(), "{method}");
            assert_eq!(server.requests(), 1, "{method}");
        }
    }

    /// An answer is never retried, whatever its status.
    #[test]
    fn a_status_is_never_retried() {
        let server = Closer::start(Then::Unavailable);
        let rt = runtime();
        let res = rt
            .block_on(server.api.send::<()>(Method::GET, "/v1/sync", None, None))
            .unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(server.requests(), 1);
    }

    /// A GET that timed out as a whole is not sent again.
    #[test]
    fn a_timed_out_get_is_not_retried() {
        let server = Closer::start(Then::Hold);
        let rt = runtime();
        let err = rt
            .block_on(async {
                server
                    .api
                    .http
                    .get(server.api.base.join("/v1/sync"))
                    .timeout(Duration::from_millis(300))
                    .send()
                    .await
            })
            .unwrap_err();
        assert!(err.is_timeout(), "{err}");
        // A second request would have had time to arrive.
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(server.requests(), 1);
    }

    /// The plain client never sends a GET twice (an agent's signed
    /// requests use it: their nonce is spent on the first copy).
    #[test]
    fn the_plain_client_never_retries() {
        let server = Closer::start(Then::CloseUnanswered);
        let rt = runtime();
        let url = server.api.base.join("/v1/sync");
        assert!(
            rt.block_on(async { http_client().unwrap().get(url).send().await })
                .is_err()
        );
        assert_eq!(server.requests(), 1);
    }
}
