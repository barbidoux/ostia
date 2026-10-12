//! FR-05: the types of report.md's "Types" table and the two name flags (`extension_mismatch`,
//! `double_extension`), with the cases of the locked `tests/acceptance/p1/test_triage.py` among them.

use ostia_core_domain::types::{DetectedType, double_extension, extension_mismatch};
use ostia_traceability::req;

#[req("FR-05")]
#[test]
fn type_names_are_the_report_ones() {
    let names: Vec<_> = DetectedType::ALL.iter().map(|t| t.name()).collect();
    assert_eq!(
        names,
        [
            "pe", "elf", "pdf", "png", "zip", "gzip", "tar", "7z", "rar", "cab", "iso9660", "msi",
            "unknown"
        ]
    );
    for detected in DetectedType::ALL {
        assert_eq!(DetectedType::from_name(detected.name()), Some(detected));
    }
    for other in ["", "PNG", "jpeg", "application/pdf", "unknown ", "exe"] {
        assert_eq!(DetectedType::from_name(other), None, "{other:?}");
    }
}

#[req("FR-05")]
#[test]
fn type_extensions_are_the_report_ones() {
    let expected: [(DetectedType, &[&str]); 13] = [
        (
            DetectedType::Pe,
            &[
                "exe", "dll", "sys", "scr", "com", "cpl", "ocx", "efi", "drv", "mui", "pyd", "ax",
            ],
        ),
        (DetectedType::Elf, &["so", "elf", "bin", "ko", "o"]),
        (DetectedType::Pdf, &["pdf"]),
        (DetectedType::Png, &["png"]),
        (
            DetectedType::Zip,
            &[
                "zip", "docx", "docm", "dotx", "xlsx", "xlsm", "pptx", "pptm", "odt", "ods", "odp",
                "jar", "apk", "epub",
            ],
        ),
        (DetectedType::Gzip, &["gz", "tgz"]),
        (DetectedType::Tar, &["tar"]),
        (DetectedType::SevenZip, &["7z"]),
        (DetectedType::Rar, &["rar"]),
        (DetectedType::Cab, &["cab"]),
        (DetectedType::Iso9660, &["iso"]),
        (DetectedType::Msi, &["msi"]),
        (DetectedType::Unknown, &[]),
    ];
    for (detected, extensions) in expected {
        assert_eq!(detected.extensions(), extensions, "{detected:?}");
    }
}

#[req("FR-05")]
#[test]
fn extension_mismatch_follows_the_report() {
    let cases = [
        // The locked triage cases.
        ("photo.png", DetectedType::Png, false),
        ("report.pdf", DetectedType::Png, true),
        ("notes.txt", DetectedType::Pdf, true),
        ("invoice.pdf.exe", DetectedType::Pe, false),
        ("setup.exe", DetectedType::Pe, false),
        ("holiday.jpg", DetectedType::Zip, true),
        ("backup.tar.gz", DetectedType::Gzip, false),
        // The last extension only, compared without regard to case.
        ("PHOTO.PNG", DetectedType::Png, false),
        ("archive.zip.pdf", DetectedType::Zip, true),
        ("a.tgz", DetectedType::Gzip, false),
        ("x.gz", DetectedType::Tar, true),
        ("module.ko", DetectedType::Elf, false),
        // A versioned shared object counts as `so`; anything else after `so` does not.
        ("libz.so.1.2", DetectedType::Elf, false),
        ("libz.so.1", DetectedType::Elf, false),
        ("libz.so.1.x", DetectedType::Elf, true),
        ("libz.so.1.2", DetectedType::Pdf, true),
        // Never for `unknown`, never without an extension.
        ("photo.png", DetectedType::Unknown, false),
        ("README", DetectedType::Pdf, false),
        (".profile", DetectedType::Pdf, false),
        // Trailing dots and spaces are dropped first, as Windows does (Q-56).
        ("report.", DetectedType::Pdf, false),
        ("report.pdf.", DetectedType::Png, true),
        ("setup.exe. ", DetectedType::Pe, false),
        ("libz.so.", DetectedType::Elf, false),
        // Case is compared in ASCII only: the Kelvin sign (U+212A) is no `k`.
        ("x.ap\u{212A}", DetectedType::Zip, true),
    ];
    for (name, detected, expected) in cases {
        assert_eq!(
            extension_mismatch(name, detected),
            expected,
            "{name} as {detected:?}"
        );
    }
}

#[req("FR-05")]
#[test]
fn double_extension_follows_the_report() {
    let cases = [
        ("invoice.pdf.exe", true),
        ("INVOICE.PDF.EXE", true),
        ("a.b.scr", true),
        (".a.b.exe", true),
        ("backup.tar.gz", false),
        ("setup.exe", false),
        ("report.pdf", false),
        ("x.exe.txt", false),
        // The first dot of a dot name belongs to the stem: one extension only.
        (".bashrc.exe", false),
        ("README", false),
        // Trailing dots and spaces are dropped first, as Windows does (Q-56).
        ("invoice.pdf.exe.", true),
        ("invoice.pdf.exe ", true),
        ("invoice.pdf.exe. .", true),
        ("invoice.exe.", false),
        // Case is compared in ASCII only: the Kelvin sign (U+212A) is no `k`.
        ("x.pdf.ln\u{212A}", false),
    ];
    for (name, expected) in cases {
        assert_eq!(double_extension(name), expected, "{name}");
    }
    for executable in [
        "exe", "scr", "com", "bat", "cmd", "pif", "cpl", "vbs", "vbe", "js", "jse", "wsf", "wsh",
        "ps1", "msi", "hta", "lnk", "jar", "dll",
    ] {
        assert!(
            double_extension(&format!("letter.txt.{executable}")),
            "{executable}"
        );
    }
}
