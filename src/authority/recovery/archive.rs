//! Immutable, content-addressed prefixes of the authenticated recovery journal.

use super::{
    AnchorHead, RecoveryError, RecoveryProfile, exact_image, read_record, recovery_bounds,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArchiveRef {
    pub head: AnchorHead,
    pub prefix_bytes: u64,
    pub prefix_sha256: [u8; 32],
}

pub struct JournalArchive {
    directory: PathBuf,
    profile: RecoveryProfile,
    max_prefix_bytes: u64,
}

impl JournalArchive {
    /// Attach the trusted, pre-provisioned archive directory. Durable archive
    /// creation and restore require Linux directory synchronization.
    pub fn new(
        directory: &Path,
        profile: RecoveryProfile,
        max_prefix_bytes: u64,
    ) -> Result<Self, RecoveryError> {
        if max_prefix_bytes == 0 {
            return Err(RecoveryError::InvalidImage);
        }
        Ok(Self {
            directory: directory_path(directory)?,
            profile,
            max_prefix_bytes,
        })
    }

    /// Retain only the prefix selected by this exact head. A staged or
    /// unanchored suffix after that prefix is never included.
    pub fn retain(&self, source: &mut File, head: AnchorHead) -> Result<ArchiveRef, RecoveryError> {
        let prefix_bytes = self.prefix_length(head)?;
        if source.metadata().map_err(io_error)?.len() < prefix_bytes {
            return Err(RecoveryError::InvalidImage);
        }
        sync_directory(&self.directory)?;
        source.sync_all().map_err(io_error)?;
        let mut staged = Staged::create(&self.directory)?;
        let prefix_sha256 = copy_prefix(source, prefix_bytes, &mut staged.file)?;
        let archive = ArchiveRef {
            head,
            prefix_bytes,
            prefix_sha256,
        };
        self.verify(&mut staged.file, archive)?;
        staged.file.sync_all().map_err(io_error)?;

        let destination = self.archive_path(archive);
        match fs::hard_link(&staged.path, &destination) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                // A concurrent or retried identical put must validate the
                // existing bytes and reestablish the directory barrier.
                self.open_verified(archive)?;
            }
            Err(_) => return Err(RecoveryError::Io),
        }
        sync_directory(&self.directory)?;
        Ok(archive)
    }

    /// Read the exact durable prefix referenced by the selected witness.
    pub fn open_verified(&self, archive: ArchiveRef) -> Result<File, RecoveryError> {
        let path = self.archive_path(archive);
        if !fs::symlink_metadata(&path).map_err(io_error)?.is_file() {
            return Err(RecoveryError::InvalidImage);
        }
        let mut file = File::open(path).map_err(io_error)?;
        self.verify(&mut file, archive)?;
        Ok(file)
    }

    /// Copy an already selected archive into a new restoration path. An
    /// existing path is never replaced, even for an identical archive.
    pub fn restore(&self, archive: ArchiveRef, destination: &Path) -> Result<(), RecoveryError> {
        let destination = self.restore_path(destination)?;
        let directory = destination.parent().ok_or(RecoveryError::InvalidImage)?;
        let mut input = self.open_verified(archive)?;
        sync_directory(directory)?;
        let mut staged = Staged::create(directory)?;
        if copy_prefix(&mut input, archive.prefix_bytes, &mut staged.file)? != archive.prefix_sha256
        {
            return Err(RecoveryError::InvalidImage);
        }
        self.verify(&mut staged.file, archive)?;
        staged.file.sync_all().map_err(io_error)?;
        match fs::hard_link(&staged.path, &destination) {
            Ok(()) => sync_directory(directory),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                Err(RecoveryError::AlreadyInitialized)
            }
            Err(_) => Err(RecoveryError::Io),
        }
    }

    pub(super) fn verify_journal_prefix(
        &self,
        file: &mut File,
        archive: ArchiveRef,
    ) -> Result<(), RecoveryError> {
        let length = self.prefix_length(archive.head)?;
        if archive.prefix_bytes != length
            || file.metadata().map_err(io_error)?.len() < length
            || copy_prefix(file, length, &mut io::sink())? != archive.prefix_sha256
        {
            return Err(RecoveryError::InvalidImage);
        }
        Ok(())
    }

    pub(super) fn verify_restored(
        &self,
        archive: ArchiveRef,
        destination: &Path,
    ) -> Result<(), RecoveryError> {
        let path = self.restore_path(destination)?;
        if !fs::symlink_metadata(&path).map_err(io_error)?.is_file() {
            return Err(RecoveryError::InvalidImage);
        }
        let mut file = File::open(&path).map_err(io_error)?;
        self.verify(&mut file, archive)?;
        file.sync_all().map_err(io_error)?;
        sync_directory(path.parent().ok_or(RecoveryError::InvalidImage)?)
    }

    fn restore_path(&self, destination: &Path) -> Result<PathBuf, RecoveryError> {
        let name = destination.file_name().ok_or(RecoveryError::InvalidImage)?;
        let directory = directory_path(destination.parent().ok_or(RecoveryError::InvalidImage)?)?;
        if directory.starts_with(&self.directory) {
            return Err(RecoveryError::InvalidImage);
        }
        Ok(directory.join(name))
    }

    fn prefix_length(&self, head: AnchorHead) -> Result<u64, RecoveryError> {
        let end = recovery_bounds::checked_end(head.offset, head.length)
            .ok_or(RecoveryError::InvalidImage)?;
        if head.profile != self.profile || head.length == 0 || end > self.max_prefix_bytes {
            return Err(RecoveryError::InvalidImage);
        }
        Ok(end)
    }

    fn verify(&self, file: &mut File, archive: ArchiveRef) -> Result<(), RecoveryError> {
        let length = self.prefix_length(archive.head)?;
        let metadata = file.metadata().map_err(io_error)?;
        if !metadata.is_file()
            || archive.prefix_bytes != length
            || metadata.len() != length
            || copy_prefix(file, length, &mut io::sink())? != archive.prefix_sha256
        {
            return Err(RecoveryError::InvalidImage);
        }
        let latest = exact_image(file, archive.head)?;
        let mut parent = latest.previous;
        while let Some(head) = parent {
            parent = read_record(file, head)?.previous;
        }
        file.seek(SeekFrom::Start(0)).map_err(io_error)?;
        Ok(())
    }

    fn archive_path(&self, archive: ArchiveRef) -> PathBuf {
        self.directory.join(format!(
            "{}.records",
            crate::wire::legacy::hex(&archive.prefix_sha256)
        ))
    }
}

fn directory_path(path: &Path) -> Result<PathBuf, RecoveryError> {
    if !path.is_absolute() || !fs::symlink_metadata(path).map_err(io_error)?.is_dir() {
        return Err(RecoveryError::InvalidImage);
    }
    fs::canonicalize(path).map_err(io_error)
}

fn io_error(_: io::Error) -> RecoveryError {
    RecoveryError::Io
}

fn copy_prefix(
    source: &mut File,
    length: u64,
    destination: &mut impl Write,
) -> Result<[u8; 32], RecoveryError> {
    source.seek(SeekFrom::Start(0)).map_err(io_error)?;
    let mut remaining = length;
    let mut hash = Sha256::new();
    let mut buffer = [0; 16 * 1024];
    while remaining > 0 {
        let read = remaining.min(buffer.len() as u64) as usize;
        source.read_exact(&mut buffer[..read]).map_err(io_error)?;
        destination.write_all(&buffer[..read]).map_err(io_error)?;
        hash.update(&buffer[..read]);
        remaining -= read as u64;
    }
    Ok(hash.finalize().into())
}

struct Staged {
    path: PathBuf,
    file: File,
}

impl Staged {
    fn create(directory: &Path) -> Result<Self, RecoveryError> {
        let nonce = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(".pending-{}-{nonce}", std::process::id()));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path).map_err(io_error)?;
        Ok(Self { path, file })
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(target_os = "linux")]
fn sync_directory(path: &Path) -> Result<(), RecoveryError> {
    File::open(path)
        .and_then(|dir| dir.sync_all())
        .map_err(io_error)
}

#[cfg(not(target_os = "linux"))]
fn sync_directory(_: &Path) -> Result<(), RecoveryError> {
    Err(RecoveryError::Io)
}

#[cfg(test)]
mod vector_tests;
