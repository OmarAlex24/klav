//! The little HTTP/1.1 the forwarder speaks itself: one request of its own
//! to the proxy at a time (the claim, the status), read to the end, and
//! the head of a local request it cannot pass on. Every call a tool makes
//! goes through as bytes (`crate::relay`): the proxy parses it.

use tokio::io::{AsyncRead, AsyncReadExt};

/// What holds a local port, as its answer to `GET /_klav/status` says
/// (papercut 12: `klav-proxy` and `klav-forward` both default to 8790).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortHolder {
    /// A `klav-forward`: it answers for its sandbox, or with a code of the
    /// proxy's or its own.
    Forwarder,
    /// A `klav-proxy` on its loopback port: it has no profile `_klav`, so it
    /// answers `403 klav_not_allowed`.
    Proxy,
    /// Another program: an answer without those.
    Other,
    /// Nothing answered in time (or nothing listens any more).
    Unknown,
}

/// The codes a forwarder answers its status with: the proxy's, and its own.
const FORWARDER_CODES: &[&str] = &[
    "klav_sandbox_revoked",
    "klav_sandbox_expired",
    "klav_agents_paused",
    "klav_proxy_unreachable",
    "klav_server_unreachable",
    "klav_rate_limited",
    "klav_proxy_store",
    "klav_forward_busy",
];

/// Asks what holds `127.0.0.1:port`, within `wait`. Sends only the
/// request `klav-forward status` sends, which no program of Klav's acts on.
pub async fn port_holder(port: u16, wait: std::time::Duration) -> PortHolder {
    use tokio::io::AsyncWriteExt;
    let asked = async {
        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .ok()?;
        tcp.write_all(
            b"GET /_klav/status HTTP/1.1\r\nhost: klav-proxy\r\nconnection: close\r\n\r\n",
        )
        .await
        .ok()?;
        read_answer(&mut tcp).await.ok()
    };
    match tokio::time::timeout(wait, asked).await {
        Ok(Some(answer)) => holder_of(&answer),
        Ok(None) | Err(_) => PortHolder::Unknown,
    }
}

/// [`port_holder`]'s reading of an answer.
pub fn holder_of(answer: &Answer) -> PortHolder {
    match answer.header("klav-error") {
        Some("klav_not_allowed") if answer.status == 403 => PortHolder::Proxy,
        Some(code) if FORWARDER_CODES.contains(&code) => PortHolder::Forwarder,
        Some(_) => PortHolder::Other,
        None if answer.status == 200
            && serde_json::from_slice::<serde_json::Value>(&answer.body)
                .is_ok_and(|v| v.get("sandbox_id").is_some()) =>
        {
            PortHolder::Forwarder
        }
        None => PortHolder::Other,
    }
}

/// The longest answer of the proxy the forwarder reads itself.
pub const MAX_ANSWER: usize = 64 * 1024;
/// The longest request head it reads before answering on its own.
pub const MAX_HEAD: usize = 16 * 1024;

/// An answer of the proxy, read whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// Its status code.
    pub status: u16,
    /// Its headers, names in lower case.
    pub headers: Vec<(String, String)>,
    /// Its body.
    pub body: Vec<u8>,
}

impl Answer {
    /// A header's value, by its lower-case name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Why an answer could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    /// The connection failed or closed before the answer was whole.
    Io,
    /// Not HTTP/1.1, or larger than [`MAX_ANSWER`].
    Malformed,
}

/// Reads one answer to a request sent with `connection: close`, to the
/// end of the connection.
pub async fn read_answer<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Answer, ReadError> {
    let mut raw = Vec::new();
    let mut limited = reader.take(u64::try_from(MAX_ANSWER + 1).unwrap_or(u64::MAX));
    // A peer that closes TLS without `close_notify` still gave the bytes it
    // sent: they are parsed, and a cut answer fails the length check.
    if limited.read_to_end(&mut raw).await.is_err() && raw.is_empty() {
        return Err(ReadError::Io);
    }
    if raw.len() > MAX_ANSWER {
        return Err(ReadError::Malformed);
    }
    parse_answer(&raw)
}

/// Parses a whole answer.
pub fn parse_answer(raw: &[u8]) -> Result<Answer, ReadError> {
    let end = find(raw, b"\r\n\r\n").ok_or(ReadError::Io)?;
    let head = std::str::from_utf8(&raw[..end]).map_err(|_| ReadError::Malformed)?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or(ReadError::Malformed)?;
    let mut parts = status_line.splitn(3, ' ');
    if parts.next() != Some("HTTP/1.1") {
        return Err(ReadError::Malformed);
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .filter(|s| (100..=599).contains(s))
        .ok_or(ReadError::Malformed)?;
    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(ReadError::Malformed)?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    let rest = &raw[end + 4..];
    let answer = |body: Vec<u8>| Answer {
        status,
        headers: headers.clone(),
        body,
    };
    let chunked = headers
        .iter()
        .any(|(n, v)| n == "transfer-encoding" && v.eq_ignore_ascii_case("chunked"));
    if chunked {
        return dechunk(rest).map(answer);
    }
    match headers.iter().find(|(n, _)| n == "content-length") {
        Some((_, len)) => {
            let len: usize = len.parse().map_err(|_| ReadError::Malformed)?;
            if rest.len() < len {
                return Err(ReadError::Io);
            }
            Ok(answer(rest[..len].to_vec()))
        }
        None => Ok(answer(rest.to_vec())),
    }
}

/// A chunked body, whole.
fn dechunk(mut rest: &[u8]) -> Result<Vec<u8>, ReadError> {
    let mut body = Vec::new();
    loop {
        let line_end = find(rest, b"\r\n").ok_or(ReadError::Io)?;
        let size_text = std::str::from_utf8(&rest[..line_end]).map_err(|_| ReadError::Malformed)?;
        let size_text = size_text.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| ReadError::Malformed)?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(body);
        }
        if rest.len() < size + 2 {
            return Err(ReadError::Io);
        }
        body.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

/// Reads a local request's head (up to the empty line), at most
/// [`MAX_HEAD`] bytes. `None` if the caller closed first or sent more.
pub async fn read_head<R: AsyncRead + Unpin>(reader: &mut R) -> Option<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1024];
    loop {
        let n = reader.read(&mut byte).await.ok()?;
        if n == 0 {
            return None;
        }
        head.extend_from_slice(&byte[..n]);
        if find(&head, b"\r\n\r\n").is_some() {
            return Some(head);
        }
        if head.len() > MAX_HEAD {
            return None;
        }
    }
}

/// An answer the forwarder makes itself: JSON with `Klav-Error`, and the
/// connection closed after it (ADR 0036 §10).
pub fn error_answer(status: u16, reason: &str, code: &str, body: &serde_json::Value) -> Vec<u8> {
    let body = body.to_string();
    format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\nklav-error: {code}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_answer_with_a_length_a_chunked_one_and_a_cut_one() {
        let a = parse_answer(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nKlav-Error: x\r\n\r\n{}")
            .expect("answer");
        assert_eq!((a.status, a.body.as_slice()), (200, &b"{}"[..]));
        assert_eq!(a.header("klav-error"), Some("x"));
        let c = parse_answer(
            b"HTTP/1.1 401 Unauthorized\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
        )
        .expect("chunked");
        assert_eq!((c.status, c.body.as_slice()), (401, &b"abcde"[..]));
        assert_eq!(
            parse_answer(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nabc"),
            Err(ReadError::Io)
        );
        assert_eq!(
            parse_answer(b"HTTP/1.0 200 OK\r\n\r\n"),
            Err(ReadError::Malformed)
        );
        assert_eq!(
            parse_answer(b"HTTP/1.1 200 OK\r\ncontent"),
            Err(ReadError::Io)
        );
    }

    #[tokio::test]
    async fn a_head_is_read_to_its_empty_line_and_no_further() {
        let mut input: &[u8] = b"GET / HTTP/1.1\r\nhost: x\r\n\r\nbody";
        let head = read_head(&mut input).await.expect("head");
        assert!(head.starts_with(b"GET / HTTP/1.1"));
        let mut huge: &[u8] = &[b'a'; MAX_HEAD + 2048];
        assert_eq!(read_head(&mut huge).await, None);
        let mut cut: &[u8] = b"GET / HTTP/1.1\r\n";
        assert_eq!(read_head(&mut cut).await, None);
    }

    #[test]
    fn the_forwarders_own_answer_says_its_code_twice() {
        let raw = error_answer(
            503,
            "Service Unavailable",
            "klav_proxy_unreachable",
            &serde_json::json!({"error": "klav_proxy_unreachable"}),
        );
        let a = parse_answer(&raw).expect("parses");
        assert_eq!(a.status, 503);
        assert_eq!(a.header("klav-error"), Some("klav_proxy_unreachable"));
        assert_eq!(a.header("connection"), Some("close"));
    }
}
