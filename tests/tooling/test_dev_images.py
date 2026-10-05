"""Disk-image smoke test (NFR-15): each file-system type is created, mounted read-only, refuses writes
and unmounts cleanly, with the development scripts tools/dev/mkimage.sh and tools/dev/loopmount.sh.

Mounting needs root. In the CI container the tests run as root; on a developer machine they call the
root-owned copy of the helper through `sudo -n`, as set up by `sudo tools/dev/setup-debian.sh --install`
and the sudoers line in docs/dev-setup.md. A missing tool, helper or sudoers rule fails the test with a
message saying what to install; nothing is skipped.
"""

import errno
import filecmp
import os
import subprocess
from pathlib import Path

import pytest

from tooling_support import REPO, run

MKIMAGE = REPO / "tools" / "dev" / "mkimage.sh"
LOOPMOUNT = REPO / "tools" / "dev" / "loopmount.sh"
INSTALLED_HELPER = Path("/usr/local/sbin/ostia-loopmount")

# (type, size in MiB): FAT32 needs at least 65525 clusters, hence 64 MiB.
FILE_SYSTEMS = [("fat32", 64), ("exfat", 16), ("ntfs", 16), ("ext4", 16)]


def loopmount(*args: str) -> subprocess.CompletedProcess[str]:
    if os.geteuid() == 0:
        return run(["bash", str(LOOPMOUNT), *args], cwd=REPO)
    assert INSTALLED_HELPER.is_file(), (
        f"{INSTALLED_HELPER} is not installed: run `sudo tools/dev/setup-debian.sh --install`"
    )
    assert filecmp.cmp(INSTALLED_HELPER, LOOPMOUNT, shallow=False), (
        f"{INSTALLED_HELPER} differs from tools/dev/loopmount.sh: run "
        "`sudo tools/dev/setup-debian.sh --install` again"
    )
    result = run(["sudo", "-n", str(INSTALLED_HELPER), *args], cwd=REPO)
    assert "a password is required" not in result.stderr, (
        "sudo -n refused the helper: add the sudoers line from docs/dev-setup.md"
    )
    return result


def mount_options(mount_point: Path) -> set[str]:
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if fields[4] == str(mount_point):
            return set(fields[5].split(","))
    raise AssertionError(f"{mount_point} is not in /proc/self/mountinfo")


@pytest.mark.req("NFR-15")
@pytest.mark.slow
@pytest.mark.parametrize(("fs_type", "size"), FILE_SYSTEMS, ids=[fs for fs, _ in FILE_SYSTEMS])
def test_image_mounts_read_only_refuses_writes_and_unmounts(
    tmp_path: Path, fs_type: str, size: int
) -> None:
    disk = tmp_path / "target" / "fixtures" / f"{fs_type}.img"
    marker = f"ostia-marker-{fs_type}\n"
    created = run(["bash", str(MKIMAGE), fs_type, str(size), str(disk)], cwd=REPO)
    assert created.returncode == 0, created.stdout + created.stderr
    assert disk.stat().st_size == size * 1024 * 1024

    # Populate the image as the fixture generator will: read-write mount of a fixtures image.
    fixture_mount = tmp_path / "target" / "mnt" / f"{fs_type}-rw"
    mounted = loopmount("rw-image", str(disk), f"{fs_type}-rw")
    assert mounted.returncode == 0, mounted.stdout + mounted.stderr
    try:
        (fixture_mount / "marker.txt").write_text(marker)
    finally:
        unmounted = loopmount("umount", str(fixture_mount))
    assert unmounted.returncode == 0, unmounted.stdout + unmounted.stderr

    scan_mount = tmp_path / "target" / "mnt" / fs_type
    mounted = loopmount("ro", str(disk), fs_type)
    assert mounted.returncode == 0, mounted.stdout + mounted.stderr
    try:
        assert (scan_mount / "marker.txt").read_text() == marker
        assert {"ro", "noexec", "nosuid", "nodev"} <= mount_options(scan_mount)
        with pytest.raises(OSError) as refused:
            (scan_mount / "new.txt").write_text("must not be written")
        assert refused.value.errno in (errno.EROFS, errno.EACCES, errno.EPERM)
    finally:
        unmounted = loopmount("umount", str(scan_mount))
    assert unmounted.returncode == 0, unmounted.stdout + unmounted.stderr
    assert not scan_mount.exists()
    assert not os.path.ismount(scan_mount)


@pytest.mark.req("NFR-15")
def test_umount_of_a_path_that_is_not_mounted_fails(tmp_path: Path) -> None:
    mount_point = tmp_path / "target" / "mnt" / "idle"
    mount_point.mkdir(parents=True)
    result = loopmount("umount", str(mount_point))
    assert result.returncode == 1
    assert f"loopmount: {mount_point} is not mounted" in result.stderr
