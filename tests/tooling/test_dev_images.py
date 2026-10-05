"""Disk-image smoke test (NFR-15): each file-system type is created, mounted read-only on a read-only loop
device, refuses writes, leaves the image unchanged and unmounts cleanly, with tools/dev/mkimage.sh and
tools/dev/loopmount.sh.

Mounting needs root. In the CI container the tests run as root; on a developer machine they call the
root-owned copy of the helper through `sudo -n`, as set up by `sudo tools/dev/setup-debian.sh --install`
and the sudoers line in docs/dev-setup.md. A missing tool, helper or sudoers rule fails the test with a
message saying what to install; nothing is skipped. Mount points live under the root-owned directory
/run/ostia-loopmount/<uid>/ (docs/questions.md Q-15).
"""

import errno
import filecmp
import hashlib
import os
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from tooling_support import REPO, run

MKIMAGE = REPO / "tools" / "dev" / "mkimage.sh"
LOOPMOUNT = REPO / "tools" / "dev" / "loopmount.sh"
INSTALLED_HELPER = Path("/usr/local/sbin/ostia-loopmount")
MOUNT_BASE = Path("/run/ostia-loopmount") / str(os.getuid())

# (mkimage type, size in MiB, blkid type): FAT32 needs at least 65525 clusters, hence 64 MiB.
FILE_SYSTEMS = [
    ("fat32", 64, "vfat"),
    ("exfat", 16, "exfat"),
    ("ntfs", 16, "ntfs"),
    ("ext4", 16, "ext4"),
]


def loopmount(*args: str, cwd: Path = REPO) -> subprocess.CompletedProcess[str]:
    if os.geteuid() == 0:
        return run(["bash", str(LOOPMOUNT), *args], cwd=cwd)
    assert INSTALLED_HELPER.is_file(), (
        f"{INSTALLED_HELPER} is not installed: run `sudo tools/dev/setup-debian.sh --install`"
    )
    assert filecmp.cmp(INSTALLED_HELPER, LOOPMOUNT, shallow=False), (
        f"{INSTALLED_HELPER} differs from tools/dev/loopmount.sh: run "
        "`sudo tools/dev/setup-debian.sh --install` again"
    )
    result = run(["sudo", "-n", str(INSTALLED_HELPER), *args], cwd=cwd)
    assert "a password is required" not in result.stderr, (
        "sudo -n refused the helper: add the sudoers line from docs/dev-setup.md"
    )
    return result


@pytest.fixture
def mounts() -> Iterator[list[str]]:
    """Mount names used by a test; whatever is still mounted at the end is unmounted."""
    names: list[str] = []
    yield names
    for name in names:
        if os.path.ismount(MOUNT_BASE / name):
            loopmount("umount", name)


def mkimage(fs_type: str, size: int, path: Path) -> None:
    created = run(["bash", str(MKIMAGE), fs_type, str(size), str(path)], cwd=REPO)
    assert created.returncode == 0, created.stdout + created.stderr


def mountinfo(mount_point: Path) -> tuple[set[str], str]:
    """Per-mount options and mount source of a mount point."""
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if fields[4] == str(mount_point):
            after = fields[fields.index("-") + 1 :]
            return set(fields[5].split(",")), after[1]
    raise AssertionError(f"{mount_point} is not in /proc/self/mountinfo")


def attached_loops(image: Path) -> str:
    return run(["losetup", "-n", "-j", str(image)], cwd=REPO).stdout.strip()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.req("NFR-15")
@pytest.mark.slow
@pytest.mark.parametrize(
    ("fs_type", "size", "blkid_type"), FILE_SYSTEMS, ids=[fs for fs, _, _ in FILE_SYSTEMS]
)
def test_image_mounts_read_only_refuses_writes_and_unmounts(
    tmp_path: Path, mounts: list[str], fs_type: str, size: int, blkid_type: str
) -> None:
    disk = tmp_path / "target" / "fixtures" / f"{fs_type}.img"
    marker = f"ostia-marker-{fs_type}\n"
    mkimage(fs_type, size, disk)
    assert disk.stat().st_size == size * 1024 * 1024
    probe = run(["blkid", "-p", "-o", "value", "-s", "TYPE", str(disk)], cwd=REPO)
    assert probe.stdout.strip() == blkid_type

    # Populate the image as the fixture generator will: read-write mount of a fixtures image.
    rw_name = f"{fs_type}-rw-{os.getpid()}"
    mounts.append(rw_name)
    mounted = loopmount("rw-image", str(disk), rw_name)
    assert mounted.returncode == 0, mounted.stdout + mounted.stderr
    assert f"({blkid_type}, " in mounted.stdout
    (MOUNT_BASE / rw_name / "marker.txt").write_text(marker)
    unmounted = loopmount("umount", rw_name)
    assert unmounted.returncode == 0, unmounted.stdout + unmounted.stderr
    assert attached_loops(disk) == ""

    before = sha256(disk)
    ro_name = f"{fs_type}-{os.getpid()}"
    mounts.append(ro_name)
    scan_mount = MOUNT_BASE / ro_name
    mounted = loopmount("ro", str(disk), ro_name)
    assert mounted.returncode == 0, mounted.stdout + mounted.stderr
    assert f"on {scan_mount}" in mounted.stdout
    assert (scan_mount / "marker.txt").read_text() == marker
    options, source = mountinfo(scan_mount)
    assert {"ro", "noexec", "nosuid", "nodev"} <= options, f"{options} ({mounted.stdout.strip()})"
    assert source.startswith("/dev/loop"), source
    loop_name = source.removeprefix("/dev/")
    assert Path(f"/sys/block/{loop_name}/ro").read_text().strip() == "1"
    with pytest.raises(OSError) as refused:
        (scan_mount / "new.txt").write_text("must not be written")
    assert refused.value.errno == errno.EROFS
    unmounted = loopmount("umount", ro_name)
    assert unmounted.returncode == 0, unmounted.stdout + unmounted.stderr
    assert not os.path.ismount(scan_mount)
    assert not scan_mount.exists()
    assert attached_loops(disk) == ""
    assert sha256(disk) == before


@pytest.mark.req("NFR-15")
def test_fat32_image_is_really_fat32(tmp_path: Path) -> None:
    disk = tmp_path / "target" / "fat32.img"
    mkimage("fat32", 64, disk)
    probe = run(["blkid", "-p", "-o", "value", "-s", "VERSION", str(disk)], cwd=REPO)
    assert probe.stdout.strip() == "FAT32"


@pytest.mark.req("TOOLING")
def test_image_owned_by_another_user_is_refused(tmp_path: Path, mounts: list[str]) -> None:
    # The helper must not mount, as root, an image the invoking user does not own. An ext4 image built
    # by the user holds target/foreign.img owned by uid 65534; once mounted, that file is reachable
    # under a valid image path but belongs to someone else.
    outer = tmp_path / "target" / "outer.img"
    mkimage("ext4", 16, outer)
    commands = tmp_path / "debugfs.cmd"
    commands.write_text(
        "mkdir target\nwrite /dev/null target/foreign.img\n"
        "set_inode_field target/foreign.img uid 65534\nset_inode_field target/foreign.img gid 65534\n"
    )
    edited = run(["debugfs", "-w", "-f", str(commands), str(outer)], cwd=REPO)
    assert edited.returncode == 0, edited.stdout + edited.stderr
    outer_name = f"outer-{os.getpid()}"
    mounts.append(outer_name)
    mounted = loopmount("ro", str(outer), outer_name)
    assert mounted.returncode == 0, mounted.stdout + mounted.stderr
    foreign = MOUNT_BASE / outer_name / "target" / "foreign.img"
    assert foreign.stat().st_uid == 65534
    inner_name = f"inner-{os.getpid()}"
    mounts.append(inner_name)
    refused = loopmount("ro", str(foreign), inner_name)
    assert refused.returncode == 2
    assert "loopmount: image is not owned by the invoking user" in refused.stderr
    assert not os.path.ismount(MOUNT_BASE / inner_name)


@pytest.mark.req("TOOLING")
def test_helper_never_imports_code_from_the_callers_directory(
    tmp_path: Path, mounts: list[str]
) -> None:
    # The caller chooses the working directory: modules found there must not run as root.
    trap_dir = tmp_path / "trap"
    trap_dir.mkdir()
    marker = tmp_path / "imported"
    for module in ("re", "fcntl", "stat", "errno"):
        (trap_dir / f"{module}.py").write_text(
            f"open({str(marker)!r}, 'a').write({module!r})\nraise SystemExit(99)\n"
        )
    disk = tmp_path / "target" / "trap.img"
    mkimage("ext4", 16, disk)
    name = f"trap-{os.getpid()}"
    mounts.append(name)
    mounted = loopmount("ro", str(disk), name, cwd=trap_dir)
    assert not marker.exists(), f"root imported {marker.read_text()}.py from the caller's directory"
    assert mounted.returncode == 0, mounted.stdout + mounted.stderr


@pytest.mark.req("TOOLING")
def test_mount_name_already_in_use_is_refused(tmp_path: Path, mounts: list[str]) -> None:
    disk = tmp_path / "target" / "busy.img"
    mkimage("ext4", 16, disk)
    name = f"busy-{os.getpid()}"
    mounts.append(name)
    first = loopmount("ro", str(disk), name)
    assert first.returncode == 0, first.stdout + first.stderr
    second = loopmount("ro", str(disk), name)
    assert second.returncode == 1
    assert f"loopmount: {MOUNT_BASE / name} is already a mount point" in second.stderr


@pytest.mark.req("TOOLING")
def test_parallel_mounts_by_the_same_user_all_succeed(tmp_path: Path, mounts: list[str]) -> None:
    disks = []
    for index in range(3):
        disk = tmp_path / "target" / f"parallel{index}.img"
        mkimage("ext4", 16, disk)
        disks.append(disk)
    names = [f"parallel{index}-{os.getpid()}" for index in range(3)]
    mounts.extend(names)
    if os.geteuid() == 0:
        prefix = ["bash", str(LOOPMOUNT)]
    else:
        # Fails fast with an explicit message when the helper or sudo is not set up.
        loopmount("umount", "warm-up-check")
        prefix = ["sudo", "-n", str(INSTALLED_HELPER)]
    commands = [[*prefix, "ro", str(disk), name] for disk, name in zip(disks, names, strict=True)]
    processes = [
        subprocess.Popen(command, cwd=REPO, text=True, stderr=subprocess.PIPE)
        for command in commands
    ]
    errors = [process.communicate()[1] for process in processes]
    assert [process.returncode for process in processes] == [0, 0, 0], errors
    for disk, name in zip(disks, names, strict=True):
        assert os.path.ismount(MOUNT_BASE / name)
        assert loopmount("umount", name).returncode == 0
        assert attached_loops(disk) == ""


@pytest.mark.req("TOOLING")
def test_umount_of_a_name_that_is_not_mounted_fails() -> None:
    name = f"idle-{os.getpid()}"
    result = loopmount("umount", name)
    assert result.returncode == 1
    assert f"loopmount: {MOUNT_BASE / name} is not mounted" in result.stderr
