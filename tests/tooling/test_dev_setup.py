"""tools/dev/setup-debian.sh --check: every tool of the development environment, its version, and the
file-system support needed for the disk-image tests (NFR-15).

The script runs with a PATH holding only fake tools written by the test, so the result does not depend on
what the machine has installed.
"""

import os
import shutil
from pathlib import Path

import pytest

from tooling_support import REPO, run

SETUP = str(REPO / "tools" / "dev" / "setup-debian.sh")
LOOPMOUNT = REPO / "tools" / "dev" / "loopmount.sh"

APT_TOOLS = {
    "git": "git",
    "curl": "curl",
    "python3": "python3",
    "gcc": "build-essential",
    "mkfs.vfat": "dosfstools",
    "mkfs.exfat": "exfatprogs",
    "mkfs.ntfs": "ntfs-3g",
    "mkfs.ext4": "e2fsprogs",
    "losetup": "mount",
    "blkid": "util-linux",
    "findmnt": "util-linux",
    "setpriv": "util-linux",
    "ntfs-3g": "ntfs-3g",
    "mount.exfat-fuse": "exfat-fuse",
    "fusermount3": "fuse3",
    "bwrap": "bubblewrap",
    "clamd": "clamav-daemon",
    "mmls": "sleuthkit",
}
USER_TOOLS = ["rustup", "cargo", "uv", "just", "cargo-nextest"]
COREUTILS = ["grep", "cmp", "head", "id", "cat", "tr", "sed", "cut", "sort", "dirname", "basename"]


def fake_environment(
    tmp_path: Path, omit: tuple[str, ...] = (), python: str = "Python 3.12.3"
) -> dict[str, str]:
    """A PATH of fake tools, a fake /proc/filesystems, a loop-control node and an installed helper."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in [*APT_TOOLS, *USER_TOOLS, "sudo"]:
        if tool in omit:
            continue
        version = python if tool == "python3" else f"{tool} 9.9"
        script = bin_dir / tool
        script.write_text(f"#!/bin/sh\necho '{version}'\n")
        script.chmod(0o755)
    for tool in COREUTILS:
        real = shutil.which(tool)
        assert real, f"{tool} is needed by the test harness"
        (bin_dir / tool).symlink_to(real)
    filesystems = tmp_path / "filesystems"
    filesystems.write_text("nodev\tsysfs\n\tvfat\n\text4\nnodev\tfuse\n\tfuseblk\n")
    loop_control = tmp_path / "loop-control"
    loop_control.write_text("")
    helper = tmp_path / "ostia-loopmount"
    shutil.copyfile(LOOPMOUNT, helper)
    return {
        "PATH": str(bin_dir),
        "HOME": str(tmp_path),
        "OSTIA_EXTRA_PATH": "",
        "OSTIA_PROC_FILESYSTEMS": str(filesystems),
        "OSTIA_LOOP_CONTROL": str(loop_control),
        "OSTIA_HELPER": str(helper),
        "OSTIA_AS_USER": "1",
    }


def check(env: dict[str, str]) -> tuple[int, list[str]]:
    result = run(["/bin/bash", SETUP, "--check"], cwd=REPO, env=env)
    return result.returncode, (result.stdout + result.stderr).splitlines()


@pytest.mark.req("NFR-15")
def test_check_lists_every_tool_with_its_version(tmp_path: Path) -> None:
    code, lines = check(fake_environment(tmp_path))
    assert code == 0, "\n".join(lines)
    for tool in [*APT_TOOLS, *USER_TOOLS]:
        version = "Python 3.12.3" if tool == "python3" else f"{tool} 9.9"
        assert f"ok: {tool}: {version}" in lines
    assert lines[-1] == "environment OK"


@pytest.mark.req("NFR-15")
def test_check_reports_how_each_file_system_is_mounted(tmp_path: Path) -> None:
    code, lines = check(fake_environment(tmp_path))
    assert code == 0, "\n".join(lines)
    assert "ok: fs vfat: kernel" in lines
    assert "ok: fs ext4: kernel" in lines
    assert "ok: fs exfat: fuse (mount.exfat-fuse)" in lines
    assert "ok: fs ntfs: fuse (ntfs-3g)" in lines
    assert "ok: loop devices: available" in lines


@pytest.mark.req("NFR-15")
@pytest.mark.parametrize(
    ("omit", "expected"),
    [
        (("mkfs.exfat",), "missing: mkfs.exfat (package exfatprogs)"),
        (("mmls",), "missing: mmls (package sleuthkit)"),
        (("cargo-nextest",), "missing: cargo-nextest (see docs/dev-setup.md)"),
        (
            ("mount.exfat-fuse",),
            "missing: fs exfat: no kernel module exfat and mount.exfat-fuse not installed",
        ),
        (("ntfs-3g",), "missing: fs ntfs: no kernel module ntfs3 and ntfs-3g not installed"),
    ],
    ids=["apt tool", "sleuth kit", "user tool", "exfat support", "ntfs support"],
)
def test_check_names_what_is_missing(tmp_path: Path, omit: tuple[str, ...], expected: str) -> None:
    code, lines = check(fake_environment(tmp_path, omit=omit))
    assert code == 1
    assert expected in lines
    assert lines[-1] == "environment incomplete"


@pytest.mark.req("NFR-15")
def test_check_refuses_an_old_python(tmp_path: Path) -> None:
    code, lines = check(fake_environment(tmp_path, python="Python 3.11.2"))
    assert code == 1
    assert "too old: python3: Python 3.11.2 (3.12 or newer required)" in lines


@pytest.mark.req("NFR-15")
def test_check_reports_a_missing_loop_control(tmp_path: Path) -> None:
    env = fake_environment(tmp_path)
    env["OSTIA_LOOP_CONTROL"] = str(tmp_path / "absent")
    code, lines = check(env)
    assert code == 1
    assert "missing: loop devices: no loop-control node" in lines


@pytest.mark.req("NFR-15")
def test_check_reports_a_stale_installed_helper(tmp_path: Path) -> None:
    env = fake_environment(tmp_path)
    Path(env["OSTIA_HELPER"]).write_text("#!/bin/sh\necho old\n")
    code, lines = check(env)
    assert code == 1
    expected = f"missing: helper {env['OSTIA_HELPER']} differs from tools/dev/loopmount.sh"
    assert expected in lines


@pytest.mark.req("NFR-15")
def test_check_reports_a_missing_sudoers_rule(tmp_path: Path) -> None:
    env = fake_environment(tmp_path)
    sudo = Path(env["PATH"]) / "sudo"
    sudo.write_text("#!/bin/sh\necho 'sudo: a password is required' >&2\nexit 1\n")
    code, lines = check(env)
    assert code == 1
    assert f"missing: sudoers rule for {env['OSTIA_HELPER']} (see docs/dev-setup.md)" in lines


@pytest.mark.req("NFR-15")
def test_install_refuses_to_run_without_root() -> None:
    # Under root (the CI container), drop to `nobody`: the refusal must hold for any unprivileged user.
    cmd = ["/bin/bash", SETUP, "--install"]
    if os.geteuid() == 0:
        cmd = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", *cmd]
    result = run(cmd, cwd=REPO)
    assert result.returncode == 2
    expected = "setup-debian: --install must run as root (sudo tools/dev/setup-debian.sh --install)"
    assert expected in result.stderr


@pytest.mark.req("NFR-15")
def test_unknown_option_is_a_usage_error() -> None:
    result = run(["/bin/bash", SETUP, "--frobnicate"], cwd=REPO)
    assert result.returncode == 2
    assert "usage: setup-debian.sh [--check | --install]" in result.stderr
