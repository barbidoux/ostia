"""tools/dev/setup-debian.sh: every tool of the development environment with its version (pinned tools
must match tools/dev/versions.env and rust-toolchain.toml), the file-system support needed by the
disk-image tests, and the --install path (NFR-15).

The script runs with a PATH holding only fake tools written by the test. Each fake answers only the exact
version arguments the script must use and fails otherwise, so the result does not depend on what the
machine has installed.
"""

import os
import shutil
import tomllib
from pathlib import Path

import pytest

from tooling_support import REPO, run

SETUP = str(REPO / "tools" / "dev" / "setup-debian.sh")
LOOPMOUNT = REPO / "tools" / "dev" / "loopmount.sh"
PINNED = dict(
    line.split("=", 1)
    for line in (REPO / "tools" / "dev" / "versions.env").read_text().splitlines()
    if "=" in line
)
with (REPO / "rust-toolchain.toml").open("rb") as toolchain_file:
    RUST = tomllib.load(toolchain_file)["toolchain"]["channel"]

# tool -> (package hint, exact arguments, version line printed)
TOOLS = {
    "git": ("package git", "--version", "git version 2.47.3"),
    "curl": ("package curl", "--version", "curl 8.14.1 (x86_64-pc-linux-gnu)"),
    "python3": ("package python3", "--version", "Python 3.13.5"),
    "gcc": ("package build-essential", "--version", "gcc (Debian 14.2.0-19) 14.2.0"),
    # mkfs.vfat has no version option: the version is the dosfstools package version (dpkg-query).
    "mkfs.vfat": ("package dosfstools", "-W -f=${Version} dosfstools", "dosfstools 4.2-1.1build1"),
    "mkfs.exfat": ("package exfatprogs", "-V", "exfatprogs version : 1.2.9"),
    "mkfs.ntfs": ("package ntfs-3g", "--version", "mkntfs v2022.10.3 (libntfs-3g)"),
    "mkfs.ext4": ("package e2fsprogs", "-V", "mke2fs 1.47.2 (1-Jan-2025)"),
    "debugfs": ("package e2fsprogs", "-V", "debugfs 1.47.2 (1-Jan-2025)"),
    "losetup": ("package mount", "--version", "losetup from util-linux 2.41"),
    "blkid": ("package util-linux", "--version", "blkid from util-linux 2.41"),
    "findmnt": ("package util-linux", "--version", "findmnt from util-linux 2.41"),
    "setpriv": ("package util-linux", "--version", "setpriv from util-linux 2.41"),
    "ntfs-3g": ("package ntfs-3g", "--version", "ntfs-3g 2022.10.3 integrated FUSE 27"),
    "mount.exfat-fuse": ("package exfat-fuse", "-V", "FUSE exfat 1.4.0 (libfuse3)"),
    "fusermount3": ("package fuse3", "-V", "fusermount3 version: 3.17.2"),
    "bwrap": ("package bubblewrap", "--version", "bubblewrap 0.11.0"),
    "clamd": ("package clamav-daemon", "--version", "ClamAV 1.4.3"),
    "mmls": ("package sleuthkit", "-V", "The Sleuth Kit ver 4.12.1"),
    "rustup": ("see docs/dev-setup.md", "--version", "rustup 1.29.1 (d95a37b6a 2026-08-13)"),
    "rustc": ("see docs/dev-setup.md", "--version", f"rustc {RUST} (b940084d7 2026-09-28)"),
    "cargo": ("see docs/dev-setup.md", "--version", f"cargo {RUST} (5f94df478 2026-08-27)"),
    "uv": ("see docs/dev-setup.md", "--version", f"uv {PINNED['UV_VERSION']} (x86_64)"),
    "just": ("see docs/dev-setup.md", "--version", f"just {PINNED['JUST_VERSION']}"),
    "cargo-nextest": (
        "see docs/dev-setup.md",
        "nextest --version",
        f"cargo-nextest-nextest {PINNED['NEXTEST_VERSION']} (abcdef 2026-09-01)",
    ),
}
COREUTILS = ["grep", "cmp", "head", "id", "cat", "tr", "sed", "cut", "sort"]


def fake_tool(bin_dir: Path, name: str, args: str, line: str) -> None:
    script = bin_dir / name
    script.write_text(f"#!/bin/sh\n[ \"$*\" = '{args}' ] || exit 1\necho '{line}'\n")
    script.chmod(0o755)


def fake_environment(
    tmp_path: Path, omit: tuple[str, ...] = (), lines: dict[str, str] | None = None
) -> dict[str, str]:
    """A PATH of fake tools, a fake /proc/filesystems, a loop-control node and an installed helper."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool, (_, args, line) in TOOLS.items():
        if tool not in omit:
            fake_tool(bin_dir, tool, args, (lines or {}).get(tool, line))
    # As the real tools do: mkfs.vfat only prints its usage; dpkg-query knows the package version;
    # mkntfs prints an empty line before its version.
    usage = bin_dir / "mkfs.vfat"
    if usage.exists():
        usage.write_text("#!/bin/sh\necho 'Usage: mkfs.vfat [OPTIONS] TARGET [BLOCKS]'\nexit 1\n")
    fake_tool(bin_dir, "dpkg-query", "-W -f=${Version} dosfstools", "4.2-1.1build1")
    ntfs = bin_dir / "mkfs.ntfs"
    if ntfs.exists():
        ntfs.write_text(
            '#!/bin/sh\n[ "$*" = "--version" ] || exit 1\n'
            "printf '\\nmkntfs v2022.10.3 (libntfs-3g)\\n\\n'\n"
        )
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
    fake_tool(bin_dir, "sudo", f"-n -l -- {helper}", str(helper))
    return {
        "PATH": str(bin_dir),
        "HOME": str(tmp_path),
        "OSTIA_EXTRA_PATH": "",
        "OSTIA_PROC_FILESYSTEMS": str(filesystems),
        "OSTIA_LOOP_CONTROL": str(loop_control),
        "OSTIA_HELPER": str(helper),
        "OSTIA_AS_USER": "1",
        "OSTIA_TEST_HOOKS": "1",
    }


def check(env: dict[str, str]) -> tuple[int, list[str]]:
    result = run(["/bin/bash", SETUP, "--check"], cwd=REPO, env=env)
    return result.returncode, (result.stdout + result.stderr).splitlines()


@pytest.mark.req("NFR-15")
def test_check_lists_every_tool_with_its_version(tmp_path: Path) -> None:
    code, lines = check(fake_environment(tmp_path))
    assert code == 0, "\n".join(lines)
    for tool, (_, _, line) in TOOLS.items():
        assert f"ok: {tool}: {line}" in lines
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
    assert f"ok: helper {tmp_path / 'ostia-loopmount'}" in lines
    assert f"ok: sudoers rule for {tmp_path / 'ostia-loopmount'}" in lines


@pytest.mark.req("NFR-15")
def test_check_prefers_kernel_drivers_and_names_missing_modules(tmp_path: Path) -> None:
    env = fake_environment(tmp_path)
    Path(env["OSTIA_PROC_FILESYSTEMS"]).write_text("\texfat\n\tntfs3\n\text4\n")
    code, lines = check(env)
    assert code == 1
    assert "ok: fs exfat: kernel" in lines
    assert "ok: fs ntfs: kernel" in lines
    assert "missing: fs vfat: no kernel module vfat" in lines


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
    code, lines = check(fake_environment(tmp_path, lines={"python3": "Python 3.11.2"}))
    assert code == 1
    assert "too old: python3: Python 3.11.2 (3.12 or newer required)" in lines


@pytest.mark.req("NFR-15")
@pytest.mark.parametrize(
    ("tool", "line", "required"),
    [
        ("just", "just 1.40.0", PINNED["JUST_VERSION"]),
        ("uv", "uv 0.11.0 (x86_64-unknown-linux-gnu)", PINNED["UV_VERSION"]),
        ("cargo-nextest", "cargo-nextest-nextest 0.9.100", PINNED["NEXTEST_VERSION"]),
        ("rustc", "rustc 1.90.0 (x 2026-01-01)", RUST),
        ("just", f"just {PINNED['JUST_VERSION']}-rc1", PINNED["JUST_VERSION"]),
        ("rustc", f"rustc {RUST}-nightly (x 2026-01-01)", RUST),
    ],
    ids=["just", "uv", "nextest", "rustc", "just pre-release", "rustc nightly"],
)
def test_check_enforces_pinned_versions(
    tmp_path: Path, tool: str, line: str, required: str
) -> None:
    code, lines = check(fake_environment(tmp_path, lines={tool: line}))
    assert code == 1
    assert f"wrong version: {tool}: {line} ({required} required)" in lines


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
    assert f"missing: helper {env['OSTIA_HELPER']} differs from tools/dev/loopmount.sh" in lines


@pytest.mark.req("NFR-15")
def test_check_reports_a_missing_sudoers_rule(tmp_path: Path) -> None:
    env = fake_environment(tmp_path)
    sudo = Path(env["PATH"]) / "sudo"
    sudo.write_text("#!/bin/sh\necho 'sudo: a password is required' >&2\nexit 1\n")
    code, lines = check(env)
    assert code == 1
    assert f"missing: sudoers rule for {env['OSTIA_HELPER']} (see docs/dev-setup.md)" in lines


@pytest.mark.req("NFR-15")
def test_check_uses_the_real_locations_by_default() -> None:
    home = os.environ.get("HOME", "/root")
    _, lines = check({"PATH": os.environ["PATH"], "HOME": home, "OSTIA_AS_USER": "1"})
    helper = [line for line in lines if " helper /usr/local/sbin/ostia-loopmount" in line]
    assert len(helper) == 1, "\n".join(lines)
    prefixes = ("ok: loop devices", "missing: loop devices")
    loops = [line for line in lines if line.startswith(prefixes)]
    assert len(loops) == 1, "\n".join(lines)


@pytest.mark.req("NFR-15")
def test_location_overrides_are_ignored_outside_tests(tmp_path: Path) -> None:
    # A stray OSTIA_* variable must not make --check look at fake files and report a false OK.
    env = fake_environment(tmp_path)
    del env["OSTIA_TEST_HOOKS"]
    _, lines = check(env)
    assert not any(str(tmp_path / "ostia-loopmount") in line for line in lines), "\n".join(lines)
    assert any(" helper /usr/local/sbin/ostia-loopmount" in line for line in lines)


def install_environment(tmp_path: Path, apt_status: int = 0) -> tuple[dict[str, str], Path]:
    """Fake root (id -u prints 0), apt-get and install that log their arguments."""
    env = fake_environment(tmp_path)
    bin_dir = Path(env["PATH"])
    log = tmp_path / "calls.log"
    (bin_dir / "id").unlink()
    for name, body in [
        ("id", '[ "$1" = "-u" ] && echo 0'),
        ("apt-get", f'echo "apt-get $*" >> {log}; exit {apt_status}'),
        ("install", f'echo "install $*" >> {log}'),
    ]:
        script = bin_dir / name
        script.write_text(f"#!/bin/sh\n{body}\n")
        script.chmod(0o755)
    return env, log


@pytest.mark.req("NFR-15")
def test_install_installs_the_package_list_and_the_root_owned_helper(tmp_path: Path) -> None:
    env, log = install_environment(tmp_path)
    result = run(["/bin/bash", SETUP, "--install"], cwd=REPO, env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    calls = log.read_text().splitlines()
    assert calls[0] == "apt-get update"
    apt_install = "apt-get install -y --no-install-recommends ca-certificates curl git "
    assert calls[1].startswith(apt_install)
    assert " dosfstools exfatprogs exfat-fuse ntfs-3g " in calls[1]
    assert calls[2] == (
        f"install -o root -g root -m 0755 {LOOPMOUNT} /usr/local/sbin/ostia-loopmount"
    )
    assert len(calls) == 3


@pytest.mark.req("NFR-15")
def test_install_stops_when_apt_fails(tmp_path: Path) -> None:
    env, log = install_environment(tmp_path, apt_status=100)
    result = run(["/bin/bash", SETUP, "--install"], cwd=REPO, env=env)
    assert result.returncode == 1
    assert "setup-debian: apt-get update failed" in result.stderr
    assert log.read_text().splitlines() == ["apt-get update"]


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
