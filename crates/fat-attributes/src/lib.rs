//! The FAT attribute byte of a file open on a vfat mount (Q-48).
//!
//! The kernel's vfat driver exposes the hidden, system and archive attributes only through the
//! `FAT_IOCTL_GET_ATTRIBUTES` ioctl. The kernel already parsed the directory entry for the mount: this crate
//! asks it for the byte it holds and parses nothing. It is the one crate of `docs/unsafe-allowlist.md`.

use std::os::fd::AsFd;

/// The attribute byte of `file` (`ATTR_RO` 0x01, `ATTR_HIDDEN` 0x02, `ATTR_SYS` 0x04, `ATTR_VOLUME` 0x08,
/// `ATTR_DIR` 0x10, `ATTR_ARCH` 0x20).
///
/// # Errors
/// The ioctl failed: `file` is not on a vfat mount (`ENOTTY`), or the kernel refused.
pub fn attributes(file: &impl AsFd) -> std::io::Result<u32> {
    let _ = file.as_fd();
    todo!("WP-1.5: the ioctl, once crates/fat-attributes is on the unsafe allowlist")
}
