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
        match self {
            Self::Pe => "pe",
            Self::Elf => "elf",
            Self::Pdf => "pdf",
            Self::Png => "png",
            Self::Zip => "zip",
            Self::Gzip => "gzip",
            Self::Tar => "tar",
            Self::SevenZip => "7z",
            Self::Rar => "rar",
            Self::Cab => "cab",
            Self::Iso9660 => "iso9660",
            Self::Msi => "msi",
            Self::Unknown => "unknown",
        }
    }

    /// The type named `name` in the report; none for any other name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|detected| detected.name() == name)
    }

    /// The extensions of the type (lower case, without the dot); none for `unknown`.
    #[must_use]
    pub fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::Pe => &[
                "exe", "dll", "sys", "scr", "com", "cpl", "ocx", "efi", "drv", "mui", "pyd", "ax",
            ],
            Self::Elf => &["so", "elf", "bin", "ko", "o"],
            Self::Pdf => &["pdf"],
            Self::Png => &["png"],
            Self::Zip => &[
                "zip", "docx", "docm", "dotx", "xlsx", "xlsm", "pptx", "pptm", "odt", "ods", "odp",
                "jar", "apk", "epub",
            ],
            Self::Gzip => &["gz", "tgz"],
            Self::Tar => &["tar"],
            Self::SevenZip => &["7z"],
            Self::Rar => &["rar"],
            Self::Cab => &["cab"],
            Self::Iso9660 => &["iso"],
            Self::Msi => &["msi"],
            Self::Unknown => &[],
        }
    }
}

/// Extensions that make a double extension dangerous (report.md `double_extension`).
const EXECUTABLE: [&str; 19] = [
    "exe", "scr", "com", "bat", "cmd", "pif", "cpl", "vbs", "vbe", "js", "jse", "wsf", "wsh",
    "ps1", "msi", "hta", "lnk", "jar", "dll",
];

/// The stem and the extensions of a name, in ASCII lower case (no other character folds: the lists are ASCII).
/// Trailing dots and spaces are dropped first, as Windows drops them when it opens a file (Q-56); the first
/// character of a dot name belongs to the stem: `.profile` has no extension, `.bashrc.exe` one.
fn split(file_name: &str) -> (String, Vec<String>) {
    let lower = file_name.trim_end_matches(['.', ' ']).to_ascii_lowercase();
    let (lead, rest) = match lower.strip_prefix('.') {
        Some(rest) => (".", rest),
        None => ("", lower.as_str()),
    };
    let mut parts = rest.split('.');
    let stem = format!("{lead}{}", parts.next().unwrap_or_default());
    (stem, parts.map(str::to_owned).collect())
}

/// The name's last extension is not one of the extensions of `detected` (report.md `extension_mismatch`).
/// Never true for `unknown` or for a name without extension (a name whose only dot is its first character has
/// none). `file_name` is the last component of the object's path.
#[must_use]
pub fn extension_mismatch(file_name: &str, detected: DetectedType) -> bool {
    let (_, extensions) = split(file_name);
    let Some(last) = extensions.last() else {
        return false;
    };
    if detected == DetectedType::Unknown {
        return false;
    }
    // A versioned shared object, `name.so.1.2`, counts as `so`.
    let versioned_so = detected == DetectedType::Elf
        && extensions
            .iter()
            .rposition(|e| e == "so")
            .is_some_and(|at| {
                extensions.get(at + 1..).is_some_and(|after| {
                    after
                        .iter()
                        .all(|e| !e.is_empty() && e.bytes().all(|b| b.is_ascii_digit()))
                })
            });
    !(versioned_so || detected.extensions().contains(&last.as_str()))
}

/// The name has at least two extensions after a non-empty stem and the last one is executable (report.md
/// `double_extension`). `file_name` is the last component of the object's path.
#[must_use]
pub fn double_extension(file_name: &str) -> bool {
    let (stem, extensions) = split(file_name);
    !stem.is_empty()
        && extensions.len() >= 2
        && extensions
            .last()
            .is_some_and(|last| EXECUTABLE.contains(&last.as_str()))
}
