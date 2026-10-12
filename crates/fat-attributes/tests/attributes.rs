//! FR-04: the FAT attribute byte comes from the kernel for a file on a vfat mount, and any other file is an
//! error, never a guessed byte. The vfat case on generated images is in `ostia-media`'s `inventory_images.rs`.

use ostia_fat_attributes::attributes;
use ostia_traceability::req;

/// ENOTTY: the ioctl does not apply to this file.
const ENOTTY: i32 = 25;

#[req("FR-04")]
#[test]
fn file_outside_a_vfat_mount_is_an_error() {
    let path = std::env::temp_dir().join(format!("ostia-fat-attributes-{}", std::process::id()));
    std::fs::write(&path, b"not on vfat").expect("file");
    let file = std::fs::File::open(&path).expect("open");
    let answer = attributes(&file);
    let _ = std::fs::remove_file(&path);
    let error = answer.expect_err("no attribute byte outside vfat");
    assert_eq!(error.raw_os_error(), Some(ENOTTY), "{error}");
}

#[req("FR-04")]
#[test]
fn directory_outside_a_vfat_mount_is_an_error() {
    let dir = std::fs::File::open(std::env::temp_dir()).expect("directory");
    let error = attributes(&dir).expect_err("no attribute byte outside vfat");
    assert_eq!(error.raw_os_error(), Some(ENOTTY), "{error}");
}
