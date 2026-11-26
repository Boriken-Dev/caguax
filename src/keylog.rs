//! TLS session secrets written to a file in the NSS key log format.

use alloc::string::String;
use alloc::sync::Arc;
use core::fmt;
use std::io::Write as _;
use std::path::Path;
use std::sync::Mutex;

/// Appends `LABEL <client random hex> <secret hex>` lines, the format Wireshark reads. The file
/// holds the secrets of every TLS connection that logs to it: protect it.
pub struct FileKeyLog {
    file: Mutex<std::fs::File>,
}

impl FileKeyLog {
    /// Opens `path` for appending, creating it (mode `0600` on Unix; an existing file keeps its
    /// mode, and a warning says when others can read it).
    ///
    /// # Errors
    ///
    /// The I/O error of opening the file.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Arc<Self>> {
        let file = crate::fileio::open_private(path.as_ref(), false, "TLS secrets")?;
        Ok(Arc::new(Self {
            file: Mutex::new(file),
        }))
    }
}

impl fmt::Debug for FileKeyLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("FileKeyLog").finish_non_exhaustive()
    }
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

impl rustls::KeyLog for FileKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let line = alloc::format!("{label} {} {}\n", hex(client_random), hex(secret));
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(error) = file.write_all(line.as_bytes()) {
            tracing::warn!(target: "caguax", %error, "the key log could not be written");
        }
    }
}
