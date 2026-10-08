//! Media access (spec §19 `media/`): read-only mounts of the analysed medium behind [`MediaAccess`].
//!
//! P1 mounts disk images through the development helper `tools/dev/loopmount.sh` ([`DevLoopMount`], WP-1.4);
//! the privileged helper of P4 replaces it behind the same trait. The orchestrator never reads the image to
//! find its file system (SEC-05): the helper's blkid does, and this crate only reads the helper's answer.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

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
    /// A recognised file system the driver refused to mount, a damaged one (exit 5).
    #[error("{0}")]
    MountFailed(String),
    /// The mount helper is missing, out of date, failed, refused its arguments, was refused by sudo or
    /// answered something unexpected (exit 5).
    #[error("{0}")]
    Helper(String),
}

impl MediaError {
    /// The report's refusal code (report.md "Refusal"), for errors that refuse the input.
    #[must_use]
    pub fn refusal_code(&self) -> Option<&'static str> {
        match self {
            Self::UnsupportedFileSystem(_) => Some("unsupported_file_system"),
            Self::MountFailed(_) | Self::Helper(_) => None,
        }
    }
}

type Release = Box<dyn Fn() -> Result<(), MediaError> + Send>;

/// A mounted medium; unmounted by [`Mounted::unmount`] or, failing that, when dropped.
pub struct Mounted {
    root: PathBuf,
    file_system: FileSystem,
    release: Option<Release>,
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
    /// A mount at `root` holding `file_system`, released by `unmount` (called once more on drop after an
    /// explicit unmount failed).
    pub fn new(
        root: PathBuf,
        file_system: FileSystem,
        unmount: impl Fn() -> Result<(), MediaError> + Send + 'static,
    ) -> Self {
        Self {
            root,
            file_system,
            release: Some(Box::new(unmount)),
        }
    }

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
    pub fn unmount(mut self) -> Result<(), MediaError> {
        let result = self.release.as_ref().map_or(Ok(()), |release| release());
        if result.is_ok() {
            self.release = None;
        }
        // On failure the release stays: dropping `self` now tries once more.
        result
    }
}

impl Drop for Mounted {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            // Nothing to report to from a drop: the explicit `unmount` reports failures.
            let _ = release();
        }
    }
}

const INSTALLED_HELPER: &str = "/usr/local/sbin/ostia-loopmount";
const HELPER_SCRIPT: &str = "tools/dev/loopmount.sh";
/// Exit code of the helper for no file system, one outside FR-03, a partition table or ambivalent
/// signatures (nothing mounted).
const UNSUPPORTED: i32 = 4;
/// Exit code of the helper when the driver refused a recognised file system (nothing mounted).
const MOUNT_REFUSED: i32 = 5;

/// Mount names unique within this process; the process id makes them unique per user.
static NEXT_MOUNT: AtomicU32 = AtomicU32::new(0);

#[derive(Debug, Clone)]
enum Helper {
    /// `tools/dev/loopmount.sh` of a repository, directly as root or through sudo and its installed copy.
    Repository(PathBuf),
    /// A program and its leading arguments.
    Command(Vec<OsString>),
}

/// Loop mounts of disk images through the development helper `tools/dev/loopmount.sh` (P1).
#[derive(Debug, Clone)]
pub struct DevLoopMount {
    helper: Helper,
}

impl DevLoopMount {
    /// The helper of the repository at `repository`: run directly when this process is root (the CI
    /// container), else through `sudo -n` and its root-owned copy `/usr/local/sbin/ostia-loopmount`
    /// (docs/dev-setup.md), which must be identical to the repository's.
    #[must_use]
    pub fn for_repository(repository: &Path) -> Self {
        Self {
            helper: Helper::Repository(repository.to_path_buf()),
        }
    }

    /// A layer that runs `command` (program and leading arguments) as its helper, with the helper's
    /// arguments appended: for another helper location, and for tests with a fake helper.
    #[must_use]
    pub fn with_helper(command: Vec<OsString>) -> Self {
        Self {
            helper: Helper::Command(command),
        }
    }

    fn command(&self) -> Result<Command, MediaError> {
        let repository = match &self.helper {
            Helper::Command(words) => {
                let (program, leading) = words
                    .split_first()
                    .ok_or_else(|| MediaError::Helper("empty mount helper command".to_owned()))?;
                let mut command = Command::new(program);
                command.args(leading);
                return Ok(command);
            }
            Helper::Repository(repository) => repository,
        };
        let script = repository.join(HELPER_SCRIPT);
        Ok(if running_as_root() {
            let mut command = Command::new("bash");
            command.arg(&script);
            command
        } else {
            let installed = std::fs::read(INSTALLED_HELPER).map_err(|error| {
                MediaError::Helper(format!(
                    "{INSTALLED_HELPER} is not installed ({error}): run `sudo tools/dev/setup-debian.sh --install`"
                ))
            })?;
            let ours = std::fs::read(&script).map_err(|error| {
                MediaError::Helper(format!("cannot read {}: {error}", script.display()))
            })?;
            if installed != ours {
                return Err(MediaError::Helper(format!(
                    "{INSTALLED_HELPER} differs from {HELPER_SCRIPT}: run `sudo tools/dev/setup-debian.sh --install` again"
                )));
            }
            let mut command = Command::new("sudo");
            command.args(["-n", INSTALLED_HELPER]);
            command
        })
    }

    fn helper(&self, args: &[&OsStr]) -> Result<Output, MediaError> {
        self.command()?
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|error| MediaError::Helper(format!("cannot run the mount helper: {error}")))
    }

    fn unmount(&self, name: &str) -> Result<(), MediaError> {
        let output = self.helper(&[OsStr::new("umount"), OsStr::new(name)])?;
        if output.status.success() {
            Ok(())
        } else {
            Err(MediaError::Helper(reason(&output)))
        }
    }
}

impl MediaAccess for DevLoopMount {
    fn mount_read_only(&self, image: &Path) -> Result<Mounted, MediaError> {
        let name = format!(
            "ostia-{}-{}",
            std::process::id(),
            NEXT_MOUNT.fetch_add(1, Ordering::Relaxed)
        );
        let output = self.helper(&[OsStr::new("ro"), image.as_os_str(), OsStr::new(&name)])?;
        match output.status.code() {
            Some(0) => {}
            Some(UNSUPPORTED) => {
                let detail = reason(&output);
                return Err(MediaError::UnsupportedFileSystem(
                    if detail.contains("unsupported file system") {
                        detail
                    } else {
                        format!("unsupported file system: {detail}")
                    },
                ));
            }
            Some(MOUNT_REFUSED) => return Err(MediaError::MountFailed(reason(&output))),
            // 1 (the helper failed), 2 (refused arguments), 3 (not root), a signal, or sudo's own refusal.
            _ => return Err(MediaError::Helper(reason(&output))),
        }
        match mounted(&output, &name) {
            Ok((root, file_system)) => {
                let layer = self.clone();
                Ok(Mounted::new(root, file_system, move || {
                    layer.unmount(&name)
                }))
            }
            // Fail closed: an answer we cannot read is never used, and the mount is not left behind.
            Err(MediaError::Helper(detail)) => Err(MediaError::Helper(match self.unmount(&name) {
                Ok(()) => detail,
                Err(unmount) => format!("{detail}; and {name} may still be mounted: {unmount}"),
            })),
            Err(other) => Err(other),
        }
    }
}

fn running_as_root() -> bool {
    // The effective uid: the second field of the `Uid:` line (the owner of /proc/self is not it for a
    // non-dumpable process).
    std::fs::read_to_string("/proc/self/status").is_ok_and(|status| {
        status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|ids| ids.split_whitespace().nth(1))
            == Some("0")
    })
}

/// The helper's last line on standard error, without its `loopmount: ` prefix; one line.
fn reason(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    stderr
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map_or_else(
            || format!("the mount helper exited with {}", output.status),
            |line| line.trim().trim_start_matches("loopmount: ").to_owned(),
        )
}

/// The mount point and file system of the helper's last line on standard output:
/// `loopmount: mounted <image> (<file system>, <driver> driver, <options>) on <mount point>`.
fn mounted(output: &Output, name: &str) -> Result<(PathBuf, FileSystem), MediaError> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let unexpected = || {
        MediaError::Helper(format!(
            "unexpected answer from the mount helper: {stdout:?}"
        ))
    };
    let line = stdout.lines().last().ok_or_else(unexpected)?;
    let rest = line
        .strip_prefix("loopmount: mounted ")
        .ok_or_else(unexpected)?;
    let (head, mount_point) = rest.rsplit_once(") on ").ok_or_else(unexpected)?;
    let (_, inside) = head.rsplit_once(" (").ok_or_else(unexpected)?;
    let variant = inside.split(", ").next().ok_or_else(unexpected)?;
    let file_system = match variant {
        "fat12" => FileSystem::Fat12,
        "fat16" => FileSystem::Fat16,
        "fat32" => FileSystem::Fat32,
        "exfat" => FileSystem::Exfat,
        "ntfs" => FileSystem::Ntfs,
        "ext2" => FileSystem::Ext2,
        "ext3" => FileSystem::Ext3,
        "ext4" => FileSystem::Ext4,
        _ => return Err(unexpected()),
    };
    let root = PathBuf::from(mount_point);
    if !root.is_absolute() || !mount_point.ends_with(&format!("/{name}")) {
        return Err(unexpected());
    }
    Ok((root, file_system))
}
