"""Argument validation of the development image scripts (tools/dev/mkimage.sh, tools/dev/loopmount.sh).

Validation runs before any privileged step, so these tests run as an ordinary user and must be refused
with exit code 2 and an explicit message. They never touch a real block device.
"""

import os
import shutil
import tempfile
from pathlib import Path

import pytest

from tooling_support import REPO, run

MKIMAGE = str(REPO / "tools" / "dev" / "mkimage.sh")
LOOPMOUNT = str(REPO / "tools" / "dev" / "loopmount.sh")
SIZE = "mkimage: size must be an integer from 1 to 4096 MiB,"
OUTPUT = "mkimage: output must be <dir>/target/[fixtures/]<name>.img"
IMAGE = "loopmount: image must be <dir>/target/[fixtures/]<name>.img"
REGULAR = "loopmount: image must be a regular file, not a symlink"
NAME = "loopmount: mount name must match [a-z0-9_-]{1,32}"
RW_IMAGE = "loopmount: rw-image only accepts <dir>/target/fixtures/<name>.img"


def mkimage(*args: str) -> tuple[int, str]:
    result = run(["bash", MKIMAGE, *args], cwd=REPO)
    return result.returncode, result.stdout + result.stderr


def loopmount(*args: str) -> tuple[int, str]:
    result = run(["bash", LOOPMOUNT, *args], cwd=REPO)
    return result.returncode, result.stdout + result.stderr


def image(tmp_path: Path, relative: str = "target/disk.img") -> Path:
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\0" * 4096)
    return path


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("args", "message"),
    [
        (("btrfs", "16", "{tmp}/target/a.img"), "mkimage: unknown file-system type 'btrfs'"),
        (("ext4", "0", "{tmp}/target/a.img"), f"{SIZE} got '0'"),
        (("ext4", "4097", "{tmp}/target/a.img"), f"{SIZE} got '4097'"),
        (("ext4", "1e3", "{tmp}/target/a.img"), f"{SIZE} got '1e3'"),
        (("ext4", "16", "/dev/sda"), "mkimage: refusing device path '/dev/sda'"),
        (("ext4", "16", "/dev/nvme0n1"), "mkimage: refusing device path '/dev/nvme0n1'"),
        (("ext4", "16", "{tmp}/a.img"), OUTPUT),
        (("ext4", "16", "{tmp}/target/../a.img"), OUTPUT),
        (("ext4", "16", "{tmp}/target/a.raw"), OUTPUT),
        (("ext4", "16"), "usage: mkimage.sh <type> <size-MiB> <output>"),
        (("ext4", "-5", "{tmp}/target/a.img"), f"{SIZE} got '-5'"),
        (("ext4", "16", "/dev/mmcblk0p1"), "mkimage: refusing device path '/dev/mmcblk0p1'"),
        (("ext4", "16", "{tmp}/target/dangling.img"), "mkimage: refusing to overwrite existing"),
    ],
    ids=[
        "unknown type",
        "size zero",
        "size over the cap",
        "size not an integer",
        "sata device",
        "nvme device",
        "outside target",
        "dot-dot escape",
        "wrong extension",
        "missing argument",
        "negative size",
        "sd card device",
        "dangling symlink output",
    ],
)
def test_mkimage_refuses_bad_arguments(tmp_path: Path, args: tuple[str, ...], message: str) -> None:
    (tmp_path / "target").mkdir()
    os.symlink(tmp_path / "nowhere", tmp_path / "target" / "dangling.img")
    code, output = mkimage(*(a.replace("{tmp}", str(tmp_path)) for a in args))
    assert code == 2
    assert message in output


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize("size", [1, 4096])
def test_mkimage_accepts_the_size_limits(tmp_path: Path, size: int) -> None:
    output = tmp_path / "target" / f"limit-{size}.img"
    code, text = mkimage("ext4", str(size), str(output))
    assert code == 0, text
    assert output.stat().st_size == size * 1024 * 1024


@pytest.mark.req("TOOLING")
def test_loopmount_accepts_a_32_character_name(tmp_path: Path) -> None:
    code, output = loopmount("ro", str(image(tmp_path, "target/disk.img")), "a" * 32)
    assert NAME not in output
    assert code != 2, output


@pytest.mark.req("TOOLING")
def test_mkimage_never_overwrites(tmp_path: Path) -> None:
    existing = image(tmp_path, "target/a.img")
    code, output = mkimage("ext4", "16", str(existing))
    assert code == 2
    assert f"mkimage: refusing to overwrite existing '{existing}'" in output
    assert existing.read_bytes() == b"\0" * 4096


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("args", "message"),
    [
        (("format", "{img}", "disk"), "loopmount: unknown mode 'format' (ro, rw-image, umount)"),
        (("ro", "/dev/sda", "disk"), "loopmount: refusing device path '/dev/sda'"),
        (("ro", "/dev/nvme0n1", "disk"), "loopmount: refusing device path '/dev/nvme0n1'"),
        (("ro", "/dev/mmcblk0p1", "disk"), "loopmount: refusing device path '/dev/mmcblk0p1'"),
        (("ro", "{tmp}/outside.img", "disk"), IMAGE),
        (("ro", "{tmp}/target", "disk"), REGULAR),
        (("ro", "{tmp}/target/link.img", "disk"), REGULAR),
        (("ro", "{img}", "../etc"), f"{NAME}, got '../etc'"),
        (("ro", "{img}", "Disk One"), f"{NAME}, got 'Disk One'"),
        (("ro", "{img}", "a" * 33), NAME),
        (("rw-image", "{img}", "disk"), RW_IMAGE),
        (("umount", "{tmp}/target/disk"), NAME),
        (("umount", "../etc"), f"{NAME}, got '../etc'"),
        (("ro", "{img}"), "usage: loopmount.sh ro|rw-image <image> <name> | umount <name>"),
    ],
    ids=[
        "unknown mode",
        "sata device",
        "nvme device",
        "sd card device",
        "outside target",
        "directory",
        "symlink",
        "name with dot-dot",
        "name with space",
        "name too long",
        "rw-image outside fixtures",
        "umount of a path",
        "umount with dot-dot",
        "missing argument",
    ],
)
def test_loopmount_refuses_bad_arguments(
    tmp_path: Path, args: tuple[str, ...], message: str
) -> None:
    real = image(tmp_path, "target/disk.img")
    image(tmp_path, "outside.img")
    os.symlink(real, tmp_path / "target" / "link.img")
    expanded = [a.replace("{img}", str(real)).replace("{tmp}", str(tmp_path)) for a in args]
    code, output = loopmount(*expanded)
    assert code == 2
    assert message in output


@pytest.mark.req("TOOLING")
def test_loopmount_without_root_says_how_to_run_it() -> None:
    # Under root (the CI container), drop to `nobody` so the unprivileged path is exercised there too.
    workdir = Path(tempfile.mkdtemp(prefix="ostia-unprivileged-"))
    try:
        workdir.chmod(0o755)
        disk = image(workdir, "target/disk.img")
        for path in (workdir / "target", disk):
            path.chmod(0o755 if path.is_dir() else 0o644)
        cmd = ["bash", LOOPMOUNT, "ro", str(disk), "disk"]
        if os.geteuid() == 0:
            cmd = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", *cmd]
        result = run(cmd, cwd=REPO)
    finally:
        shutil.rmtree(workdir)
    assert result.returncode == 3, result.stdout + result.stderr
    assert "loopmount: needs root: run `sudo -n /usr/local/sbin/ostia-loopmount" in result.stderr
