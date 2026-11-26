//! Writing files that hold secrets: owner-only and replaced whole.

use alloc::string::String;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Writes `data` to `path` through a new file of mode `0600` with a random name beside it, then
/// renames it over `path`: a reader sees the old file or the new one, a planted file or symlink at
/// a guessable name is never written through, and on Unix only the owner can read the result.
/// On Windows the file keeps its directory's access list.
pub(crate) fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
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
    {
        use std::os::unix::fs::DirBuilderExt;
        missing.mode(0o700);
    }
    missing.create(directory)?;
    let (temporary, mut file) = create_temporary(directory, &name)?;
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

fn create_temporary(directory: &Path, name: &str) -> io::Result<(PathBuf, fs::File)> {
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
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&temporary) {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => last = error,
            Err(error) => return Err(error),
        }
    }
    Err(last)
}
