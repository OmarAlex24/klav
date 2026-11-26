//! How Klav Cloud's enclave and its parent reach each other (ADR 0051 §1):
//! `AF_VSOCK` on a Nitro instance, loopback TCP everywhere else, so every
//! test of the enclave and the parent runs on macOS and Linux alike.
//!
//! An [`Endpoint`] is written `tcp:HOST:PORT` or `vsock:CID:PORT`. Vsock
//! exists only on Linux; elsewhere it is refused when parsed.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite};

/// A byte stream of either transport.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

/// A boxed [`Io`].
pub type BoxIo = Box<dyn Io>;

/// Accepts connections.
pub trait Listener: Send + Sync + 'static {
    /// The next connection.
    fn accept(&self) -> BoxFuture<'_, io::Result<BoxIo>>;
}

/// Opens connections to one place.
pub trait Connector: Send + Sync + 'static {
    /// A new connection.
    fn connect(&self) -> BoxFuture<'_, io::Result<BoxIo>>;
}

/// Where to listen or connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    /// TCP.
    Tcp(SocketAddr),
    /// vsock: a context ID and a port (Linux only).
    Vsock {
        /// The context ID: the enclave's, as `nitro-cli describe-enclaves`
        /// reports it, `3` for the parent seen from the enclave
        /// (`VMADDR_CID_PARENT`), or `4294967295` (`VMADDR_CID_ANY`) to
        /// listen on every one.
        cid: u32,
        /// The port.
        port: u32,
    },
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(addr) => write!(f, "tcp:{addr}"),
            Self::Vsock { cid, port } => write!(f, "vsock:{cid}:{port}"),
        }
    }
}

impl std::str::FromStr for Endpoint {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        if let Some(addr) = s.strip_prefix("tcp:") {
            return addr
                .parse()
                .map(Self::Tcp)
                .map_err(|_| format!("{s:?} is not tcp:IP:PORT"));
        }
        if let Some(rest) = s.strip_prefix("vsock:") {
            let (cid, port) = rest
                .split_once(':')
                .and_then(|(c, p)| Some((c.parse().ok()?, p.parse().ok()?)))
                .ok_or_else(|| format!("{s:?} is not vsock:CID:PORT"))?;
            if !cfg!(target_os = "linux") {
                return Err("vsock exists only on Linux".into());
            }
            return Ok(Self::Vsock { cid, port });
        }
        Err(format!("{s:?} is neither tcp:IP:PORT nor vsock:CID:PORT"))
    }
}

impl Endpoint {
    /// Listens on it.
    pub async fn listen(&self) -> io::Result<Box<dyn Listener>> {
        match *self {
            Self::Tcp(addr) => Ok(Box::new(TcpAcceptor(
                tokio::net::TcpListener::bind(addr).await?,
            ))),
            Self::Vsock { cid, port } => vsock_listen(cid, port),
        }
    }

    /// A connector to it.
    pub fn connector(&self) -> Arc<dyn Connector> {
        match *self {
            Self::Tcp(addr) => Arc::new(TcpTarget(addr)),
            Self::Vsock { cid, port } => vsock_connector(cid, port),
        }
    }
}

/// A TCP listener.
pub struct TcpAcceptor(pub tokio::net::TcpListener);

impl TcpAcceptor {
    /// The address it listens on.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

impl Listener for TcpAcceptor {
    fn accept(&self) -> BoxFuture<'_, io::Result<BoxIo>> {
        Box::pin(async move {
            let (stream, _) = self.0.accept().await?;
            stream.set_nodelay(true)?;
            Ok(Box::new(stream) as BoxIo)
        })
    }
}

/// Connects to a TCP address.
pub struct TcpTarget(pub SocketAddr);

impl Connector for TcpTarget {
    fn connect(&self) -> BoxFuture<'_, io::Result<BoxIo>> {
        Box::pin(async move {
            let stream = tokio::net::TcpStream::connect(self.0).await?;
            stream.set_nodelay(true)?;
            Ok(Box::new(stream) as BoxIo)
        })
    }
}

#[cfg(all(
    target_os = "linux",
    any(feature = "enclave", feature = "nitro-parent")
))]
mod vsock_impl {
    use super::*;
    use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

    pub(super) struct VsockAcceptor(pub(super) VsockListener);

    impl Listener for VsockAcceptor {
        fn accept(&self) -> BoxFuture<'_, io::Result<BoxIo>> {
            Box::pin(async move {
                let (stream, _) = self.0.accept().await?;
                Ok(Box::new(stream) as BoxIo)
            })
        }
    }

    pub(super) struct VsockTarget(pub(super) VsockAddr);

    impl Connector for VsockTarget {
        fn connect(&self) -> BoxFuture<'_, io::Result<BoxIo>> {
            Box::pin(async move {
                let stream = VsockStream::connect(self.0).await?;
                Ok(Box::new(stream) as BoxIo)
            })
        }
    }

    pub(super) fn listen(cid: u32, port: u32) -> io::Result<Box<dyn Listener>> {
        Ok(Box::new(VsockAcceptor(VsockListener::bind(
            VsockAddr::new(cid, port),
        )?)))
    }

    pub(super) fn connector(cid: u32, port: u32) -> Arc<dyn Connector> {
        Arc::new(VsockTarget(VsockAddr::new(cid, port)))
    }
}

#[cfg(all(
    target_os = "linux",
    any(feature = "enclave", feature = "nitro-parent")
))]
fn vsock_listen(cid: u32, port: u32) -> io::Result<Box<dyn Listener>> {
    vsock_impl::listen(cid, port)
}

#[cfg(all(
    target_os = "linux",
    any(feature = "enclave", feature = "nitro-parent")
))]
fn vsock_connector(cid: u32, port: u32) -> Arc<dyn Connector> {
    vsock_impl::connector(cid, port)
}

/// Parsing refuses vsock off Linux, so these are never reached there.
#[cfg(not(all(
    target_os = "linux",
    any(feature = "enclave", feature = "nitro-parent")
)))]
fn vsock_listen(_cid: u32, _port: u32) -> io::Result<Box<dyn Listener>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "vsock exists only on Linux",
    ))
}

#[cfg(not(all(
    target_os = "linux",
    any(feature = "enclave", feature = "nitro-parent")
)))]
fn vsock_connector(_cid: u32, _port: u32) -> Arc<dyn Connector> {
    Arc::new(Unsupported)
}

#[cfg(not(all(
    target_os = "linux",
    any(feature = "enclave", feature = "nitro-parent")
)))]
struct Unsupported;

#[cfg(not(all(
    target_os = "linux",
    any(feature = "enclave", feature = "nitro-parent")
)))]
impl Connector for Unsupported {
    fn connect(&self) -> BoxFuture<'_, io::Result<BoxIo>> {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "vsock exists only on Linux",
            ))
        })
    }
}

/// Moves bytes both ways until either side closes, or neither moves a
/// byte for `idle`. Returns the bytes moved `(a to b, b to a)`.
pub async fn relay(
    a: &mut BoxIo,
    b: &mut BoxIo,
    idle: std::time::Duration,
) -> io::Result<(u64, u64)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    let mut up = 0u64;
    let mut down = 0u64;
    let mut abuf = vec![0u8; 16 * 1024];
    let mut bbuf = vec![0u8; 16 * 1024];
    let mut a_open = true;
    let mut b_open = true;
    while a_open || b_open {
        let step = tokio::time::timeout(idle, async {
            tokio::select! {
                n = ar.read(&mut abuf), if a_open => (true, n),
                n = br.read(&mut bbuf), if b_open => (false, n),
            }
        })
        .await;
        let Ok((from_a, n)) = step else {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "idle"));
        };
        let n = n?;
        if from_a {
            if n == 0 {
                a_open = false;
                bw.shutdown().await.ok();
            } else {
                bw.write_all(&abuf[..n]).await?;
                up += n as u64;
            }
        } else if n == 0 {
            b_open = false;
            aw.shutdown().await.ok();
        } else {
            aw.write_all(&bbuf[..n]).await?;
            down += n as u64;
        }
    }
    Ok((up, down))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_parse() {
        assert_eq!(
            "tcp:127.0.0.1:8443".parse::<Endpoint>(),
            Ok(Endpoint::Tcp("127.0.0.1:8443".parse().expect("addr")))
        );
        assert_eq!(
            "tcp:[::1]:443".parse::<Endpoint>(),
            Ok(Endpoint::Tcp("[::1]:443".parse().expect("addr")))
        );
        assert!("tcp:localhost:443".parse::<Endpoint>().is_err());
        assert!("vsock:3".parse::<Endpoint>().is_err());
        assert!("udp:1.2.3.4:5".parse::<Endpoint>().is_err());
        let vsock = "vsock:16:5000".parse::<Endpoint>();
        if cfg!(target_os = "linux") {
            assert_eq!(
                vsock,
                Ok(Endpoint::Vsock {
                    cid: 16,
                    port: 5000
                })
            );
        } else {
            assert!(vsock.is_err());
        }
    }

    #[tokio::test]
    async fn a_relay_moves_both_ways_and_counts() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpAcceptor(
            tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind"),
        );
        let addr = listener.local_addr().expect("addr");
        let echo = tokio::spawn(async move {
            let mut s = listener.accept().await.expect("accept");
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.expect("read");
            s.write_all(b"world!").await.expect("write");
            s.shutdown().await.ok();
        });
        let front = TcpAcceptor(
            tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind"),
        );
        let front_addr = front.local_addr().expect("addr");
        let relayed = tokio::spawn(async move {
            let mut a = front.accept().await.expect("accept");
            let mut b = TcpTarget(addr).connect().await.expect("connect");
            relay(&mut a, &mut b, std::time::Duration::from_secs(5)).await
        });
        let mut client = tokio::net::TcpStream::connect(front_addr)
            .await
            .expect("connect");
        client.write_all(b"hello").await.expect("write");
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.expect("read");
        assert_eq!(got, b"world!");
        drop(client);
        echo.await.expect("echo");
        let (up, down) = relayed.await.expect("relay").expect("relay ok");
        assert_eq!((up, down), (5, 6));
    }
}
