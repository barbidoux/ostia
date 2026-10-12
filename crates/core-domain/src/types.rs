//! Object types identified from the content (FR-05) and the risk flags of a name (`docs/contracts/report.md`,
//! "Objects" and "Types").
//!
//! The type comes from the triage worker, which reads the content (SEC-05); this module only names the types
//! and compares a file name with the type: names are metadata, no content is read here.

/// A type of report.md's "Types" table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetectedType {
    /// `MZ` header whose `e_lfanew` points to `PE\0\0`.
    Pe,
    /// `\x7fELF`.
    Elf,
    /// `%PDF-`.
    Pdf,
    /// The PNG signature.
    Png,
    /// `PK\x03\x04`, or an empty archive's `PK\x05\x06`.
    Zip,
    /// `\x1f\x8b`.
    Gzip,
    /// `ustar` at offset 257.
    Tar,
    /// The 7z signature.
    SevenZip,
    /// `Rar!\x1a\x07`.
    Rar,
    /// `MSCF`.
    Cab,
    /// `CD001` at offset 32769.
    Iso9660,
    /// Compound file whose root CLSID is the Windows Installer package one.
    Msi,
    /// None of the above.
    Unknown,
}

impl DetectedType {
    /// Every type, in report.md's order.
    pub const ALL: [Self; 13] = [
        Self::Pe,
        Self::Elf,
        Self::Pdf,
        Self::Png,
        Self::Zip,
        Self::Gzip,
        Self::Tar,
        Self::SevenZip,
        Self::Rar,
        Self::Cab,
        Self::Iso9660,
        Self::Msi,
        Self::Unknown,
    ];

    /// The type's name in the report (`detected_type`).
    #[must_use]
    pub fn name(self) -> &'static str {
        let _ = self;
        todo!("WP-1.7")
    }

    /// The type named `name` in the report; none for any other name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        let _ = name;
        todo!("WP-1.7")
    }

    /// The extensions of the type (lower case, without the dot); none for `unknown`.
    #[must_use]
    pub fn extensions(self) -> &'static [&'static str] {
        let _ = self;
        todo!("WP-1.7")
    }
}

/// The name's last extension is not one of the extensions of `detected` (report.md `extension_mismatch`).
/// Never true for `unknown` or for a name without extension (a name whose only dot is its first character has
/// none). `file_name` is the last component of the object's path.
#[must_use]
pub fn extension_mismatch(file_name: &str, detected: DetectedType) -> bool {
    let _ = (file_name, detected);
    todo!("WP-1.7")
}

/// The name has at least two extensions after a non-empty stem and the last one is executable (report.md
/// `double_extension`). `file_name` is the last component of the object's path.
#[must_use]
pub fn double_extension(file_name: &str) -> bool {
    let _ = file_name;
    todo!("WP-1.7")
}
