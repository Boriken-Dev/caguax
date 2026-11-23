//! Recording what passes through the proxy: a hook, a log line per session, and capture files.
//!
//! A [`Recorder`] sees each relayed connection as a [`Session`]: when it opens, every chunk each
//! side sends, when each direction ends, and when it closes. What it sees is what crossed the
//! proxy's upstream side: the plaintext of a TLS route (the proxy made, or ended, that TLS) and
//! of the request and response heads it rewrote; the ciphertext of a tunnel it only relayed.
//! Plaintext of a mutual-TLS session is as sensitive as the credentials that opened it.
//!
//! A recorder that returns an error is logged and gets nothing more of that session; traffic is
//! never affected.

mod log;
#[cfg(feature = "pcap")]
mod pcap;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::net::SocketAddr;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::Mutex;
use std::time::SystemTime;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub use log::LogRecorder;
#[cfg(feature = "pcap")]
#[cfg_attr(docsrs, doc(cfg(feature = "pcap")))]
pub use pcap::{PcapFormat, PcapRecorder};

use crate::connection::Connection;
use crate::route::Route;

/// Which side of a relayed connection sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sender {
    /// The client of the proxy.
    Client,
    /// The destination, or the upstream proxy that tunnels to it.
    Server,
}

impl Sender {
    /// `client` or `server`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }
}

/// A recorder could not record; the text says why and holds no traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordError(String);

impl RecordError {
    /// An error with this reason.
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

impl fmt::Display for RecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl core::error::Error for RecordError {}

/// One relayed connection, as recorders see it.
#[derive(Debug, Clone)]
pub struct Session {
    id: u64,
    connection: Connection,
    route: Route,
    client: Option<SocketAddr>,
    server: Option<SocketAddr>,
    started: SystemTime,
}

impl Session {
    /// A session record; the server numbers its sessions from 1.
    pub fn new(
        id: u64,
        connection: Connection,
        route: Route,
        client: Option<SocketAddr>,
        server: Option<SocketAddr>,
    ) -> Self {
        Self {
            id,
            connection,
            route,
            client,
            server,
            started: SystemTime::now(),
        }
    }

    /// The session's number, unique within one server.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// What the rules saw.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// What the router decided.
    pub fn route(&self) -> &Route {
        &self.route
    }

    /// The client's address.
    pub fn client(&self) -> Option<SocketAddr> {
        self.client
    }

    /// The address the proxy connected to: the destination, or the upstream proxy that tunnelled
    /// to it.
    pub fn server(&self) -> Option<SocketAddr> {
        self.server
    }

    /// When the session opened.
    pub fn started(&self) -> SystemTime {
        self.started
    }
}

/// What the server calls for each relayed connection, in order per session; each call returns
/// quickly. Every method has a default that records nothing.
pub trait Recorder: Send + Sync {
    /// A session opened.
    ///
    /// # Errors
    ///
    /// A [`RecordError`] drops this recorder for this session.
    fn opened(&self, session: &Session) -> Result<(), RecordError> {
        let _ = session;
        Ok(())
    }

    /// `sender` sent `data`.
    ///
    /// # Errors
    ///
    /// A [`RecordError`] drops this recorder for this session.
    fn data(&self, session: &Session, sender: Sender, data: &[u8]) -> Result<(), RecordError> {
        let _ = (session, sender, data);
        Ok(())
    }

    /// `sender`'s direction has no more data.
    ///
    /// # Errors
    ///
    /// A [`RecordError`] drops this recorder for this session.
    fn ended(&self, session: &Session, sender: Sender) -> Result<(), RecordError> {
        let _ = (session, sender);
        Ok(())
    }

    /// The session closed.
    ///
    /// # Errors
    ///
    /// A [`RecordError`] is logged.
    fn closed(&self, session: &Session) -> Result<(), RecordError> {
        let _ = session;
        Ok(())
    }
}

/// The server's side of a session: fans one session out to its recorders and drops one that fails.
pub struct Recording {
    session: Session,
    state: Mutex<RecordingState>,
}

struct RecordingState {
    recorders: Vec<Arc<dyn Recorder>>,
    ended: Vec<Sender>,
    closed: bool,
}

impl fmt::Debug for Recording {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Recording")
            .field("session", &self.session.id)
            .finish_non_exhaustive()
    }
}

impl Recording {
    /// Opens `session` on `recorders`; `None` with no recorder.
    pub fn start(recorders: &[Arc<dyn Recorder>], session: Session) -> Option<Arc<Self>> {
        if recorders.is_empty() {
            return None;
        }
        let recording = Arc::new(Self {
            session,
            state: Mutex::new(RecordingState {
                recorders: recorders.to_vec(),
                ended: Vec::new(),
                closed: false,
            }),
        });
        recording.each("opened", |recorder, session| recorder.opened(session));
        Some(recording)
    }

    /// The session being recorded.
    pub fn session(&self) -> &Session {
        &self.session
    }

    fn each(&self, stage: &str, call: impl Fn(&dyn Recorder, &Session) -> Result<(), RecordError>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .recorders
            .retain(|recorder| match call(recorder.as_ref(), &self.session) {
                Ok(()) => true,
                Err(error) => {
                    tracing::warn!(
                        target: "caguax",
                        session = self.session.id,
                        stage,
                        %error,
                        "a recorder failed and gets nothing more of this session"
                    );
                    false
                }
            });
    }

    /// `sender` sent `data`.
    pub fn data(&self, sender: Sender, data: &[u8]) {
        if !data.is_empty() {
            self.each("data", |recorder, session| {
                recorder.data(session, sender, data)
            });
        }
    }

    /// `sender`'s direction ended (reported once).
    pub fn ended(&self, sender: Sender) {
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.ended.contains(&sender) {
                return;
            }
            state.ended.push(sender);
        }
        self.each("ended", |recorder, session| recorder.ended(session, sender));
    }

    /// The session is over: both directions end, then it closes (reported once).
    pub fn closed(&self) {
        self.ended(Sender::Client);
        self.ended(Sender::Server);
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.closed {
                return;
            }
            state.closed = true;
        }
        self.each("closed", |recorder, session| recorder.closed(session));
    }
}

/// Wraps the upstream side of a relay so everything that crosses it is recorded: what the proxy
/// writes is the client's, what it reads the server's. Dropping it closes the session.
pub struct RecordedStream<S> {
    inner: S,
    recording: Option<Arc<Recording>>,
}

impl<S> RecordedStream<S> {
    /// Records `inner` when there is a recording; otherwise passes it through.
    pub fn new(inner: S, recording: Option<Arc<Recording>>) -> Self {
        Self { inner, recording }
    }
}

impl<S> fmt::Debug for RecordedStream<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordedStream")
            .field("recording", &self.recording)
            .finish_non_exhaustive()
    }
}

impl<S> Drop for RecordedStream<S> {
    fn drop(&mut self) {
        if let Some(recording) = &self.recording {
            recording.closed();
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RecordedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if let (Poll::Ready(Ok(())), Some(recording)) = (&result, &self.recording) {
            let fresh = &buffer.filled()[before..];
            if fresh.is_empty() {
                recording.ended(Sender::Server);
            } else {
                recording.data(Sender::Server, fresh);
            }
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RecordedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(context, data);
        if let (Poll::Ready(Ok(written)), Some(recording)) = (&result, &self.recording) {
            recording.data(Sender::Client, &data[..*written]);
        }
        result
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
        let result = Pin::new(&mut self.inner).poll_shutdown(context);
        if let (Poll::Ready(_), Some(recording)) = (&result, &self.recording) {
            recording.ended(Sender::Client);
        }
        result
    }
}
