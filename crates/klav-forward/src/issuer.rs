//! A sandbox issuer's requests to Klav Cloud's hosted proxy (ADR 0051
//! §6.1, §6.4) over the account's pinned channel: TLS 1.3 to
//! `a<agent_id>.<endpoint>`, the proxy accepted only with the pin from the
//! issuer's own grant, a fresh channel key as the client's raw public key
//! (RFC 7250), and one HTTP/1.1 request inside the tunnel.
//!
//! TLS ends inside the enclave, so the host that relays the bytes never
//! sees the request or the answer: the answer to a start carries the
//! sandbox's one-time secret (threat T276). The public API of the hosted
//! proxy (`proxy.klav.dev`, TLS ended at the load balancer) never carries
//! an issuer request.
//!
//! The issuer authenticates with its signature (spec §13.3), in the
//! headers the caller gives, not with the channel key: the key is fresh
//! for every request and is never bound to a sandbox, which the proxy
//! checks. Nothing here signs as an agent or holds a vault key: the
//! request arrives signed.

use std::sync::Arc;
use std::time::Duration;

use klav_core::crypto::channel::TlsSigner;
use klav_core::crypto::sandbox::PIN_LEN;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

use crate::forward::CONNECT_TIMEOUT;
use crate::http::{MAX_ANSWER, ReadError};

/// Why a request to the hosted proxy failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerIoError {
    /// No connection, or the handshake failed (the proxy did not present
    /// the pinned key): no byte of the request left.
    Unreachable,
    /// The request may have left, and no whole answer came back.
    Lost,
    /// The arguments: a name that is not a DNS name, or a header with a
    /// line break. Nothing was sent.
    Invalid,
}

/// An answer whose body may hold a secret (a start's one-time secret):
/// the status and the body, in a buffer wiped on drop. Not `Debug`, not
/// `Clone`.
pub struct SecretAnswer {
    /// The status code.
    pub status: u16,
    /// The body, already de-chunked.
    pub body: Zeroizing<Vec<u8>>,
}

/// One request of the issuer.
pub struct IssuerRequest<'a> {
    /// The address to dial, `HOST:PORT`: the channel's own name and port,
    /// or another address that relays to it (tests, and
    /// `KLAV_HOSTED_PROXY_CHANNEL_ADDR`). The pin, not the address,
    /// authenticates the proxy.
    pub address: &'a str,
    /// The channel name, `a<agent_id hex>.<endpoint>`: the SNI the enclave
    /// picks the account's key by, and the request's `Host`.
    pub name: &'a str,
    /// The pin from the issuer's grant: `SHA-256` of the proxy's SPKI.
    pub pin: [u8; PIN_LEN],
    /// `GET` or `POST`.
    pub method: &'a str,
    /// The path and the signed query.
    pub path: &'a str,
    /// The signature headers (and nothing with a line break).
    pub headers: &'a [(&'a str, String)],
    /// The body (JSON), or empty.
    pub body: &'a [u8],
    /// How long the whole request may take.
    pub wait: Duration,
}

/// Sends `req` over a new pinned channel connection and reads its answer
/// (sent with `connection: close`) to the end.
pub async fn send(req: &IssuerRequest<'_>) -> Result<SecretAnswer, IssuerIoError> {
    let name =
        ServerName::try_from(req.name.to_ascii_lowercase()).map_err(|_| IssuerIoError::Invalid)?;
    if !matches!(name, ServerName::DnsName(_))
        || !req.method.bytes().all(|b| b.is_ascii_uppercase())
        || [req.path, req.name].iter().any(|v| has_break(v))
        || req
            .headers
            .iter()
            .any(|(n, v)| has_break(n) || has_break(v))
    {
        return Err(IssuerIoError::Invalid);
    }
    let config = crate::channel::client_config(TlsSigner::channel_key(), req.pin)
        .map_err(|_| IssuerIoError::Invalid)?;
    let connect = async {
        let tcp = TcpStream::connect(req.address).await?;
        tcp.set_nodelay(true)?;
        TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await
    };
    let mut tls = tokio::time::timeout(CONNECT_TIMEOUT, connect)
        .await
        .map_err(|_| IssuerIoError::Unreachable)?
        .map_err(|_| IssuerIoError::Unreachable)?;
    let mut head = format!(
        "{} {} HTTP/1.1\r\nhost: {}\r\nconnection: close\r\ncontent-length: {}\r\n",
        req.method,
        req.path,
        req.name.to_ascii_lowercase(),
        req.body.len()
    );
    if !req.body.is_empty() {
        head.push_str("content-type: application/json\r\n");
    }
    for (n, v) in req.headers {
        head.push_str(n);
        head.push_str(": ");
        head.push_str(v);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    let mut bytes = Zeroizing::new(head.into_bytes());
    bytes.extend_from_slice(req.body);
    let run = async {
        tls.write_all(&bytes)
            .await
            .map_err(|_| IssuerIoError::Lost)?;
        tls.flush().await.map_err(|_| IssuerIoError::Lost)?;
        read_secret_answer(&mut tls)
            .await
            .map_err(|_| IssuerIoError::Lost)
    };
    tokio::time::timeout(req.wait, run)
        .await
        .map_err(|_| IssuerIoError::Lost)?
}

fn has_break(v: &str) -> bool {
    v.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

/// Reads one answer to a request sent with `connection: close`, to the
/// end of the connection, without a copy of its body outside a buffer
/// wiped on drop: the raw bytes are read into one buffer sized up front
/// (so it never moves), and the body is cut out of it in place.
pub async fn read_secret_answer<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<SecretAnswer, ReadError> {
    // Room for the limit and the probe past it, so `read_to_end` never
    // grows (and so never copies) the buffer.
    let mut raw = Zeroizing::new(Vec::with_capacity(MAX_ANSWER + 1024));
    let mut limited = reader.take(u64::try_from(MAX_ANSWER + 1).unwrap_or(u64::MAX));
    if limited.read_to_end(&mut raw).await.is_err() && raw.is_empty() {
        return Err(ReadError::Io);
    }
    if raw.len() > MAX_ANSWER {
        return Err(ReadError::Malformed);
    }
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(ReadError::Io)?;
    let (status, length, chunked) = {
        let head = std::str::from_utf8(&raw[..end]).map_err(|_| ReadError::Malformed)?;
        let mut lines = head.split("\r\n");
        let mut parts = lines.next().ok_or(ReadError::Malformed)?.splitn(3, ' ');
        if parts.next() != Some("HTTP/1.1") {
            return Err(ReadError::Malformed);
        }
        let status: u16 = parts
            .next()
            .and_then(|s| s.parse().ok())
            .filter(|s| (100..=599).contains(s))
            .ok_or(ReadError::Malformed)?;
        let mut length = None;
        let mut chunked = false;
        for line in lines {
            let (name, value) = line.split_once(':').ok_or(ReadError::Malformed)?;
            let (name, value) = (name.trim(), value.trim());
            if name.eq_ignore_ascii_case("content-length") {
                length = Some(value.parse::<usize>().map_err(|_| ReadError::Malformed)?);
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                chunked = value.eq_ignore_ascii_case("chunked");
            }
        }
        (status, length, chunked)
    };
    let start = end + 4;
    let mut body = raw;
    if chunked {
        // De-chunked in place: each piece moves toward the front of the
        // same buffer.
        let mut read = start;
        let mut write = 0;
        loop {
            let line_end = body[read..]
                .windows(2)
                .position(|w| w == b"\r\n")
                .ok_or(ReadError::Io)?
                + read;
            let size_text =
                std::str::from_utf8(&body[read..line_end]).map_err(|_| ReadError::Malformed)?;
            let size_text = size_text.split(';').next().unwrap_or_default().trim();
            let size = usize::from_str_radix(size_text, 16).map_err(|_| ReadError::Malformed)?;
            read = line_end + 2;
            if size == 0 {
                break;
            }
            if body.len() < read + size + 2 {
                return Err(ReadError::Io);
            }
            body.copy_within(read..read + size, write);
            write += size;
            read += size + 2;
        }
        body.truncate(write);
    } else {
        let len = match length {
            Some(len) if body.len() - start < len => return Err(ReadError::Io),
            Some(len) => len,
            None => body.len() - start,
        };
        body.copy_within(start..start + len, 0);
        body.truncate(len);
    }
    Ok(SecretAnswer { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn parse(raw: &[u8]) -> Result<SecretAnswer, ReadError> {
        let mut r = raw;
        read_secret_answer(&mut r).await
    }

    #[tokio::test]
    async fn reads_a_sized_and_a_chunked_answer() {
        let a = parse(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello")
            .await
            .expect("sized");
        assert_eq!((a.status, a.body.as_slice()), (200, &b"hello"[..]));
        let a = parse(b"HTTP/1.1 401 Unauthorized\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n")
            .await
            .expect("chunked");
        assert_eq!((a.status, a.body.as_slice()), (401, &b"abcde"[..]));
    }

    #[tokio::test]
    async fn a_cut_or_foreign_answer_is_refused() {
        assert!(matches!(
            parse(b"HTTP/1.1 200 OK\r\ncontent-length: 9\r\n\r\nhello").await,
            Err(ReadError::Io)
        ));
        assert!(matches!(
            parse(b"HTTP/1.0 200 OK\r\n\r\n").await,
            Err(ReadError::Malformed)
        ));
        assert!(matches!(parse(b"HTTP/1.1 200").await, Err(ReadError::Io)));
    }

    #[tokio::test]
    async fn a_header_with_a_line_break_is_never_sent() {
        let headers = [("klav-agent", "x\r\nevil: 1".to_owned())];
        let req = IssuerRequest {
            address: "127.0.0.1:9",
            name: "a00.proxy.klav.test",
            pin: [0; PIN_LEN],
            method: "GET",
            path: "/_klav/sandboxes",
            headers: &headers,
            body: b"",
            wait: Duration::from_secs(1),
        };
        assert_eq!(send(&req).await.err(), Some(IssuerIoError::Invalid));
        let ip = IssuerRequest {
            name: "127.0.0.1",
            headers: &[],
            ..req
        };
        assert_eq!(send(&ip).await.err(), Some(IssuerIoError::Invalid));
    }
}
