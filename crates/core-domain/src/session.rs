//! Session, medium and device (spec §14, "Domain objects").

/// Transfer mode of a session (FR-10, FR-21, spec §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Mode {
    /// Default: a MALICIOUS or UNSCANNABLE object blocks the medium (FR-10).
    #[default]
    Compliant,
    /// Non-compliant: only CLEAN objects are transferable, whatever else the medium holds.
    Selective,
    /// Nothing is transferable.
    ScanOnly,
}

/// The signed policy a session runs with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRef {
    /// The policy's `version`.
    pub version: String,
    /// SHA-256 of the exact policy file bytes.
    pub sha256: [u8; 32],
}

/// One medium insertion, end to end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// Unique per run.
    pub id: String,
    /// Transfer mode.
    pub mode: Mode,
    /// The policy.
    pub policy: PolicyRef,
}

/// Role of a medium.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MediumRole {
    /// The medium being analysed.
    Input,
    /// The kiosk-formatted target (P4).
    Output,
}

/// File systems of FR-03.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileSystem {
    /// FAT12.
    Fat12,
    /// FAT16.
    Fat16,
    /// FAT32.
    Fat32,
    /// exFAT.
    Exfat,
    /// NTFS.
    Ntfs,
    /// ext2.
    Ext2,
    /// ext3.
    Ext3,
    /// ext4.
    Ext4,
}

/// An input or output medium.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Medium {
    /// Input or output.
    pub role: MediumRole,
    /// The file system, when recognised.
    pub file_system: Option<FileSystem>,
    /// Size in bytes.
    pub size: u64,
}

/// The USB device behind a medium: a placeholder until the USB defence of P4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Device;
