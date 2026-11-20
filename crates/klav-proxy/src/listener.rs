//! The local listener with a cap on open connections: one more waits in
//! the kernel's backlog until another closes.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::serve::Listener;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// A [`TcpListener`] that holds at most `max` connections open.
pub struct Limited {
    inner: TcpListener,
    slots: Arc<Semaphore>,
}

impl Limited {
    /// `inner`, capped at `max` open connections.
    pub fn new(inner: TcpListener, max: usize) -> Self {
        Self {
            inner,
            slots: Arc::new(Semaphore::new(max)),
        }
    }
}

/// A connection and its slot, given back when it closes.
pub struct Slotted {
    io: TcpStream,
    _slot: OwnedSemaphorePermit,
}

impl Listener for Limited {
    type Io = Slotted;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        // The semaphore is never closed.
        let slot = Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .expect("open semaphore");
        let (io, addr) = Listener::accept(&mut self.inner).await;
        (Slotted { io, _slot: slot }, addr)
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

impl AsyncRead for Slotted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Slotted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_connection_over_the_cap_waits_for_a_slot() {
        let inner = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = inner.local_addr().unwrap();
        let mut limited = Limited::new(inner, 1);
        let _a = TcpStream::connect(addr).await.unwrap();
        let (first, _) = limited.accept().await;
        let _b = TcpStream::connect(addr).await.unwrap();
        let waiting =
            tokio::time::timeout(std::time::Duration::from_millis(200), limited.accept()).await;
        assert!(waiting.is_err(), "the second connection waits");
        drop(first);
        let second =
            tokio::time::timeout(std::time::Duration::from_secs(2), limited.accept()).await;
        assert!(second.is_ok(), "and gets the slot once the first closes");
    }
}
