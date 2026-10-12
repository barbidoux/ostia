//! The FAT attribute byte of a file open on a vfat mount (Q-48).
//!
//! The kernel's vfat driver exposes the hidden, system and archive attributes only through the
//! `FAT_IOCTL_GET_ATTRIBUTES` ioctl. The kernel already parsed the directory entry for the mount: this crate
//! asks it for the byte it holds and parses nothing. It is the one crate of `docs/unsafe-allowlist.md`.

use std::os::fd::{AsFd, AsRawFd};

mod ioctl {
    // FAT_IOCTL_GET_ATTRIBUTES = _IOR('r', 0x10, __u32) (linux/msdos_fs.h).
    nix::ioctl_read!(fat_get_attributes, b'r', 0x10, u32);
}

/// The attribute byte of `file` (`ATTR_RO` 0x01, `ATTR_HIDDEN` 0x02, `ATTR_SYS` 0x04, `ATTR_VOLUME` 0x08,
/// `ATTR_DIR` 0x10, `ATTR_ARCH` 0x20).
///
/// # Errors
/// The ioctl failed: `file` is not on a vfat mount (`ENOTTY`), or the kernel refused.
pub fn attributes(file: &impl AsFd) -> std::io::Result<u32> {
    let fd = file.as_fd();
    let mut bits: u32 = 0;
    // SAFETY: FAT_IOCTL_GET_ATTRIBUTES writes exactly one u32 through its argument, which points to `bits`, a
    // live, aligned, writable u32 on this stack frame; `fd` is borrowed from `file` and stays open for the call.
    // A file system that does not know the request returns ENOTTY without writing.
    let answer = unsafe { ioctl::fat_get_attributes(fd.as_raw_fd(), &raw mut bits) };
    answer.map_err(std::io::Error::from)?;
    Ok(bits)
}
