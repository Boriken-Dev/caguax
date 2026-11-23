//! Copying bytes both ways between two streams until both directions end.

use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};

/// How [`relay`] copies.
#[derive(Debug, Clone, Copy)]
pub struct RelayOptions {
    /// Ends a direction that receives nothing for this long (`None`: never).
    pub idle_timeout: Option<Duration>,
    /// The copy buffer of each direction.
    pub buffer: usize,
    /// Bounds the wait for a peer's reply to a shutdown.
    pub close_timeout: Duration,
    /// With TLS on either side a half-close cannot be passed on, so one direction ending ends
    /// both.
    pub end_both: bool,
}

async fn pump<R, W>(mut from: R, mut to: W, options: RelayOptions)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = alloc::vec![0_u8; options.buffer.max(1)];
    loop {
        let read = match options.idle_timeout {
            Some(idle) => match tokio::time::timeout(idle, from.read(&mut buffer)).await {
                Ok(read) => read,
                Err(_) => break,
            },
            None => from.read(&mut buffer).await,
        };
        match read {
            Ok(0) | Err(_) => break,
            Ok(count) => {
                if to.write_all(&buffer[..count]).await.is_err() || to.flush().await.is_err() {
                    break;
                }
            }
        }
    }
    // Pass the end on: a half-close where the transport has one, a TLS close_notify otherwise.
    let _ = tokio::time::timeout(options.close_timeout, to.shutdown()).await;
}

/// Relays until both directions have ended. Connection errors end the relay quietly: either side
/// going away is how a proxied connection normally finishes.
pub async fn relay<A, B>(client: A, upstream: B, options: RelayOptions)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);
    let up = pump(client_read, upstream_write, options);
    let down = pump(upstream_read, client_write, options);
    if options.end_both {
        tokio::select! {
            () = up => {}
            () = down => {}
        }
    } else {
        tokio::join!(up, down);
    }
}

/// Ends a read that stays silent too long with a timeout error.
#[derive(Debug)]
pub struct IdleRead<S> {
    inner: S,
    idle: Option<Duration>,
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S> IdleRead<S> {
    /// Wraps `inner`; `None` never times out.
    pub fn new(inner: S, idle: Option<Duration>) -> Self {
        Self {
            inner,
            idle,
            timer: None,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for IdleRead<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_read(context, buffer) {
            Poll::Ready(result) => {
                this.timer = None;
                Poll::Ready(result)
            }
            Poll::Pending => {
                let Some(idle) = this.idle else {
                    return Poll::Pending;
                };
                let timer = this
                    .timer
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(idle)));
                if timer.as_mut().poll(context).is_ready() {
                    this.timer = None;
                    return Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()));
                }
                Poll::Pending
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for IdleRead<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, data)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}
