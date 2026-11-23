//! A `tracing` event per session opened and closed.

use alloc::collections::BTreeMap;
use std::sync::Mutex;

use tracing::Level;

use super::{RecordError, Recorder, Sender, Session};

/// The `tracing` target of the events this recorder emits.
pub const TARGET: &str = "caguax::traffic";

/// Logs each session's opening and closing, with the octets each way, at a level (default
/// `INFO`) under the `tracing` target `caguax::traffic`.
///
/// A `tracing` target is a constant, so a label of your own goes in the `logger` field of each
/// event ([`with_target`](Self::with_target)).
#[derive(Debug)]
pub struct LogRecorder {
    logger: &'static str,
    level: Level,
    counts: Mutex<BTreeMap<u64, [u64; 2]>>,
}

impl LogRecorder {
    /// A recorder at `INFO` whose `logger` field is `caguax::traffic`.
    pub fn new() -> Self {
        Self {
            logger: TARGET,
            level: Level::INFO,
            counts: Mutex::new(BTreeMap::new()),
        }
    }

    /// The label placed in the `logger` field of each event.
    #[must_use]
    pub fn with_target(mut self, logger: &'static str) -> Self {
        self.logger = logger;
        self
    }

    /// The level of each event.
    #[must_use]
    pub fn with_level(mut self, level: Level) -> Self {
        self.level = level;
        self
    }

    /// The label in each event's `logger` field.
    pub fn target(&self) -> &'static str {
        self.logger
    }

    /// The level of each event.
    pub fn level(&self) -> Level {
        self.level
    }

    fn emit(&self, message: core::fmt::Arguments<'_>) {
        let logger = self.logger;
        match self.level {
            Level::ERROR => tracing::error!(target: "caguax::traffic", logger, "{message}"),
            Level::WARN => tracing::warn!(target: "caguax::traffic", logger, "{message}"),
            Level::INFO => tracing::info!(target: "caguax::traffic", logger, "{message}"),
            Level::DEBUG => tracing::debug!(target: "caguax::traffic", logger, "{message}"),
            Level::TRACE => tracing::trace!(target: "caguax::traffic", logger, "{message}"),
        }
    }

    fn counts(&self) -> std::sync::MutexGuard<'_, BTreeMap<u64, [u64; 2]>> {
        self.counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Default for LogRecorder {
    fn default() -> Self {
        Self::new()
    }
}

impl Recorder for LogRecorder {
    fn opened(&self, session: &Session) -> Result<(), RecordError> {
        self.counts().insert(session.id(), [0, 0]);
        let client = session
            .client()
            .map_or_else(|| "?".into(), |address| address.to_string());
        self.emit(format_args!(
            "#{} open {client} -> {} ({})",
            session.id(),
            session.connection().authority(),
            session.route().action()
        ));
        Ok(())
    }

    fn data(&self, session: &Session, sender: Sender, data: &[u8]) -> Result<(), RecordError> {
        if let Some(counts) = self.counts().get_mut(&session.id()) {
            let slot = usize::from(sender == Sender::Server);
            counts[slot] += data.len() as u64;
        }
        Ok(())
    }

    fn closed(&self, session: &Session) -> Result<(), RecordError> {
        let [sent, received] = self.counts().remove(&session.id()).unwrap_or([0, 0]);
        self.emit(format_args!(
            "#{} closed {}: {sent} octets sent, {received} received",
            session.id(),
            session.connection().authority()
        ));
        Ok(())
    }
}
