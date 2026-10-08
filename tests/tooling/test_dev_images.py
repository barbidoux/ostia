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
import importlib
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
    assert f"({fs_type}, " in mounted.stdout
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


def super_options(mount_point: Path) -> set[str]:
    """Options of the file system mounted on a mount point (the field after the source in mountinfo)."""
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if fields[4] == str(mount_point):
            return set(fields[fields.index("-") + 3].split(","))
    raise AssertionError(f"{mount_point} is not in /proc/self/mountinfo")


@pytest.mark.req("NFR-15")
@pytest.mark.parametrize("mode", ["rw-image", "ro"])
def test_fat_is_mounted_with_utf8_names_and_utc_times(
    tmp_path: Path, mounts: list[str], mode: str
) -> None:
    # Kernel defaults are iocharset=ascii and the kernel time zone: a FAT name outside ASCII would be
    # refused and FAT times (no zone on disk) would shift with the machine (docs/questions.md Q-44).
    disk = tmp_path / "target" / "fixtures" / "utf8.img"
    mkimage("fat16", 16, disk)
    name = f"fat-{mode}-{os.getpid()}"
    mounts.append(name)
    mounted = loopmount(mode, str(disk), name)
    assert mounted.returncode == 0, mounted.stdout + mounted.stderr
    assert {"utf8", "tz=UTC"} <= super_options(MOUNT_BASE / name)
    unmounted = loopmount("umount", name)
    assert unmounted.returncode == 0, unmounted.stdout + unmounted.stderr


@pytest.mark.req("NFR-15")
def test_fat_name_outside_ascii_is_written_and_read_back(tmp_path: Path, mounts: list[str]) -> None:
    disk = tmp_path / "target" / "fixtures" / "names.img"
    mkimage("fat16", 16, disk)
    planted = "caf\N{LATIN SMALL LETTER E WITH ACUTE} \N{RIGHT-TO-LEFT OVERRIDE}txt.exe"
    writer = f"fat-names-rw-{os.getpid()}"
    mounts.append(writer)
    mounted = loopmount("rw-image", str(disk), writer)
    assert mounted.returncode == 0, mounted.stdout + mounted.stderr
    (MOUNT_BASE / writer / planted).write_bytes(b"trapped name")
    assert loopmount("umount", writer).returncode == 0
    reader = f"fat-names-{os.getpid()}"
    mounts.append(reader)
    mounted = loopmount("ro", str(disk), reader)
    assert mounted.returncode == 0, mounted.stdout + mounted.stderr
    assert os.listdir(MOUNT_BASE / reader) == [planted]
    assert (MOUNT_BASE / reader / planted).read_bytes() == b"trapped name"
    assert loopmount("umount", reader).returncode == 0


VARIANTS = ["fat12", "fat16", "fat32", "exfat", "ntfs", "ext2", "ext3", "ext4"]
SIZES = {"fat32": 64}


@pytest.mark.req("FR-03")
@pytest.mark.parametrize("variant", VARIANTS)
def test_mount_reports_the_file_system_in_the_report_vocabulary(
    tmp_path: Path, mounts: list[str], variant: str
) -> None:
    # The mount layer reports what the helper's blkid found (SEC-05: it never reads the image itself);
    # FAT12, FAT16 and FAT32 are told apart (report.md `medium.file_system`).
    disk = tmp_path / "target" / f"{variant}.img"
    mkimage(variant, SIZES.get(variant, 16), disk)
    name = f"variant-{variant}-{os.getpid()}"
    mounts.append(name)
    mounted = loopmount("ro", str(disk), name)
    assert mounted.returncode == 0, mounted.stdout + mounted.stderr
    assert f" ({variant}, " in mounted.stdout, mounted.stdout
    assert mounted.stdout.rstrip().endswith(f") on {MOUNT_BASE / name}"), mounted.stdout


def blank(path: Path, size_mib: int = 4) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as image:
        image.truncate(size_mib * 1024 * 1024)
    return path


@pytest.mark.req("FR-03")
@pytest.mark.parametrize("kind", ["blank", "minix"])
def test_unsupported_file_system_exits_4_and_mounts_nothing(
    tmp_path: Path, mounts: list[str], kind: str
) -> None:
    disk = blank(tmp_path / "target" / f"{kind}.img")
    if kind == "minix":
        made = run(["mkfs.minix", "-3", str(disk)], cwd=REPO)
        assert made.returncode == 0, made.stdout + made.stderr
    name = f"unsupported-{kind}-{os.getpid()}"
    mounts.append(name)
    refused = loopmount("ro", str(disk), name)
    assert refused.returncode == 4, refused.stdout + refused.stderr
    expected = "none" if kind == "blank" else "minix"
    assert f"loopmount: unsupported file system '{expected}'" in refused.stderr
    assert not (MOUNT_BASE / name).exists()
    assert attached_loops(disk) == ""


GENERATOR = importlib.import_module("tests.fixtures.images")


def file_system_type(mount_point: Path) -> str:
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if fields[4] == str(mount_point):
            return fields[fields.index("-") + 1]
    raise AssertionError(f"{mount_point} is not in /proc/self/mountinfo")


@pytest.mark.req("FR-03", "FR-04")
@pytest.mark.parametrize("variant", ["ext2", "ext3"])
def test_ext2_and_ext3_are_read_with_the_ext4_driver_and_their_attributes(
    mounts: list[str], variant: str
) -> None:
    # The ext2 driver may be built without xattr support (WSL2): the ext4 driver reads all three
    # (docs/questions.md Q-45, Q-46).
    planted = {
        "path": "tagged.txt",
        "content": b"tagged",
        "hidden": False,
        "read_only": False,
        "modified": None,
        "streams": {},
        "xattrs": {"user.comment": b"planted"},
        "symlink": None,
    }
    image = Path(GENERATOR.build_image(variant, [planted]))
    name = f"extdriver-{variant}-{os.getpid()}"
    mounts.append(name)
    mounted = loopmount("ro", str(image), name)
    assert mounted.returncode == 0, mounted.stdout + mounted.stderr
    assert f" ({variant}, " in mounted.stdout, mounted.stdout
    assert file_system_type(MOUNT_BASE / name) == "ext4"
    assert os.getxattr(MOUNT_BASE / name / "tagged.txt", "user.comment") == b"planted"


@pytest.mark.req("FR-03", "FR-04")
def test_ntfs_is_read_with_ntfs_3g_and_its_streams(mounts: list[str]) -> None:
    # The kernel ntfs3 driver does not show alternate data streams; ntfs-3g shows them as user.* attributes.
    planted = {
        "path": "host.txt",
        "content": b"host",
        "hidden": False,
        "read_only": False,
        "modified": None,
        "streams": {"Zone.Identifier": b"[ZoneTransfer]\r\nZoneId=3\r\n"},
        "xattrs": {},
        "symlink": None,
    }
    image = Path(GENERATOR.build_image("ntfs", [planted]))
    name = f"ntfsdriver-{os.getpid()}"
    mounts.append(name)
    mounted = loopmount("ro", str(image), name)
    assert mounted.returncode == 0, mounted.stdout + mounted.stderr
    assert file_system_type(MOUNT_BASE / name) == "fuseblk"
    host = MOUNT_BASE / name / "host.txt"
    assert os.getxattr(host, "user.Zone.Identifier") == b"[ZoneTransfer]\r\nZoneId=3\r\n"
    with pytest.raises(OSError) as refused:
        host.write_bytes(b"must not be written")
    assert refused.value.errno == errno.EROFS


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
