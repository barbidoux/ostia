//! Media access (spec §19 `media/`): read-only mounts of the analysed medium behind [`MediaAccess`].
//!
//! P1 mounts disk images through the development helper `tools/dev/loopmount.sh` ([`DevLoopMount`], WP-1.4);
//! the privileged helper of P4 replaces it behind the same trait. The orchestrator never reads the image to
//! find its file system (SEC-05): the helper's blkid does, and this crate only reads the helper's answer.

use std::fmt;
use std::path::{Path, PathBuf};

use ostia_core_domain::session::FileSystem;

/// Read-only access to the file system of a medium.
pub trait MediaAccess {
    /// Mount the file system of `image` read-only.
    ///
    /// # Errors
    /// [`MediaError::UnsupportedFileSystem`] when the image holds no file system of FR-03,
    /// [`MediaError::MountFailed`] when a supported one cannot be mounted, [`MediaError::Helper`] when the
    /// mount helper itself fails.
    fn mount_read_only(&self, image: &Path) -> Result<Mounted, MediaError>;
}

/// Why a medium could not be mounted. Each message is one line.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MediaError {
    /// No file system, or one outside FR-03: the input is refused (`unsupported_file_system`, exit 4). The
    /// message contains the words `unsupported file system` (cli.md).
    #[error("{0}")]
    UnsupportedFileSystem(String),
    /// A supported file system that cannot be mounted, a damaged one included (exit 5).
    #[error("{0}")]
    MountFailed(String),
    /// The mount helper is missing, out of date, refused its arguments or answered something unexpected
    /// (exit 5).
    #[error("{0}")]
    Helper(String),
}

impl MediaError {
    /// The report's refusal code (report.md "Refusal"), for errors that refuse the input.
    #[must_use]
    pub fn refusal_code(&self) -> Option<&'static str> {
        todo!("WP-1.4: refusal code")
    }
}

/// A mounted medium; unmounted by [`Mounted::unmount`] or, failing that, when dropped.
pub struct Mounted {
    root: PathBuf,
    file_system: FileSystem,
}

impl fmt::Debug for Mounted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mounted")
            .field("root", &self.root)
            .field("file_system", &self.file_system)
            .finish_non_exhaustive()
    }
}

impl Mounted {
    /// The directory where the file system is mounted.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The file system the helper found.
    #[must_use]
    pub fn file_system(&self) -> FileSystem {
        self.file_system
    }

    /// Unmount the medium.
    ///
    /// # Errors
    /// [`MediaError::Helper`] when the helper cannot unmount it.
    pub fn unmount(self) -> Result<(), MediaError> {
        todo!("WP-1.4: unmount")
    }
}

/// Loop mounts of disk images through the development helper `tools/dev/loopmount.sh` (P1).
#[derive(Debug, Clone)]
pub struct DevLoopMount {
    repository: PathBuf,
}

impl DevLoopMount {
    /// The helper of the repository at `repository`: run directly when this process is root (the CI
    /// container), else through `sudo -n` and its root-owned copy `/usr/local/sbin/ostia-loopmount`
    /// (docs/dev-setup.md).
    #[must_use]
    pub fn for_repository(repository: &Path) -> Self {
        Self {
            repository: repository.to_path_buf(),
        }
    }
}

impl MediaAccess for DevLoopMount {
    fn mount_read_only(&self, image: &Path) -> Result<Mounted, MediaError> {
        todo!(
            "WP-1.4: mount {} with {}",
            image.display(),
            self.repository.display()
        )
    }
}
