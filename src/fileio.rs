//! Writing files that hold secrets: owner-only and replaced whole.

use alloc::string::String;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Writes `data` to `path` so that a reader sees the old file or the new one, never part of
/// either: a new file with a random name beside it (`create_new`, so a planted file or symlink is
/// never written through) is renamed over `path`. With `private` the file is mode `0600` on Unix
/// and the missing directories `0700`; on Windows the file keeps its directory's access list.
pub(crate) fn write_whole(path: &Path, data: &[u8], private: bool) -> io::Result<()> {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut missing = fs::DirBuilder::new();
    missing.recursive(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::DirBuilderExt;
        missing.mode(0o700);
    }
    missing.create(directory)?;
    let (temporary, mut file) = create_temporary(directory, &name, private)?;
    let result = (|| {
        file.write_all(data)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// [`write_whole`] with `private` set.
pub(crate) fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    write_whole(path, data, true)
}

/// Opens `path` for appending (or, with `truncate`, replacing the content), creating it with mode
/// `0600` on Unix. A file that already exists keeps its mode: when that lets others read it, a
/// warning says so (`what` names what the file holds).
pub(crate) fn open_private(path: &Path, truncate: bool, what: &str) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true);
    if truncate {
        options.truncate(true);
    } else {
        options.append(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file.metadata()?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            tracing::warn!(
                target: "caguax",
                "{} holds {what} and is accessible to others (mode {mode:03o}); restrict it to its owner",
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    let _ = what;
    Ok(file)
}

fn create_temporary(
    directory: &Path,
    name: &str,
    private: bool,
) -> io::Result<(PathBuf, fs::File)> {
    let mut last = io::Error::from(io::ErrorKind::AlreadyExists);
    for _ in 0..16 {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(|error| io::Error::other(error.to_string()))?;
        let suffix: String = random
            .iter()
            .map(|byte| alloc::format!("{byte:02x}"))
            .collect();
        let temporary = directory.join(alloc::format!(".{name}.{suffix}.tmp"));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(not(unix))]
        let _ = private;
        match options.open(&temporary) {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => last = error,
            Err(error) => return Err(error),
        }
    }
    Err(last)
}
