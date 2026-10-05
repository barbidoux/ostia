"""The dev container and CI build the same Debian environment from the same lists (NFR-15).

`tools/dev/packages.txt` (Debian packages) and `tools/dev/versions.env` (tool versions) are the single
sources: the setup script, the dev container and both CI jobs read them instead of repeating them.
"""

import json
import re
from pathlib import Path

import pytest

from tooling_support import REPO

DEV = REPO / "tools" / "dev"
DOCKERFILE = REPO / ".devcontainer" / "Dockerfile"
DEVCONTAINER = REPO / ".devcontainer" / "devcontainer.json"
CI = REPO / ".github" / "workflows" / "ci.yml"


def read(path: Path) -> str:
    assert path.is_file(), f"{path.relative_to(REPO)} is missing"
    return path.read_text(encoding="utf-8")


def job(name: str) -> str:
    match = re.search(rf"^  {re.escape(name)}:\n((?:(?!  \S).*\n|\n)*)", read(CI), re.MULTILINE)
    assert match, f"job {name!r} not found"
    return match.group(1)


def packages() -> set[str]:
    lines = read(DEV / "packages.txt").splitlines()
    return {line.split("#")[0].strip() for line in lines if line.split("#")[0].strip()}


@pytest.mark.req("NFR-15")
def test_package_list_covers_the_image_and_analysis_tools() -> None:
    assert {
        "ca-certificates",
        "curl",
        "git",
        "build-essential",
        "python3",
        "dosfstools",
        "exfatprogs",
        "exfat-fuse",
        "ntfs-3g",
        "e2fsprogs",
        "fuse3",
        "mount",
        "util-linux",
        "bubblewrap",
        "clamav-daemon",
        "sleuthkit",
    } <= packages()


@pytest.mark.req("NFR-15")
def test_versions_file_pins_every_downloaded_tool() -> None:
    entries = dict(
        line.split("=", 1) for line in read(DEV / "versions.env").splitlines() if "=" in line
    )
    assert set(entries) == {"UV_VERSION", "JUST_VERSION", "NEXTEST_VERSION"}
    for value in entries.values():
        assert re.fullmatch(r"\d+\.\d+\.\d+", value), value


@pytest.mark.req("NFR-15")
def test_dev_container_is_debian_stable_built_from_the_single_sources() -> None:
    dockerfile = read(DOCKERFILE)
    assert re.search(r"^FROM debian:13\b", dockerfile, re.MULTILINE)
    assert "tools/dev/packages.txt" in dockerfile
    assert "tools/dev/versions.env" in dockerfile
    assert "rust-toolchain.toml" in dockerfile
    config = json.loads(read(DEVCONTAINER))
    assert config["build"]["dockerfile"] == "Dockerfile"
    assert config["build"]["context"] == ".."


@pytest.mark.req("NFR-15")
@pytest.mark.parametrize("name", ["ci", "acceptance-current"])
def test_ci_jobs_use_the_single_sources(name: str) -> None:
    text = job(name)
    assert "tools/dev/packages.txt" in text
    assert "tools/dev/versions.env" in text
    assert not re.search(r"(UV|JUST|NEXTEST)_VERSION: \"", read(CI)), "versions repeated in ci.yml"


@pytest.mark.req("NFR-15")
@pytest.mark.parametrize("name", ["ci", "acceptance-current"])
def test_ci_jobs_can_attach_loop_devices(name: str) -> None:
    container = r"^    container:\n      image: debian:13\n      options: --privileged$"
    assert re.search(container, job(name), re.MULTILINE)


@pytest.mark.req("NFR-15")
def test_setup_script_installs_the_package_list_and_the_helper() -> None:
    script = read(DEV / "setup-debian.sh")
    assert "packages.txt" in script
    assert "install -o root -g root -m 0755" in script
    assert "/usr/local/sbin/ostia-loopmount" in script


@pytest.mark.req("NFR-15")
def test_dev_setup_documents_the_sudoers_line() -> None:
    doc = read(REPO / "docs" / "dev-setup.md")
    assert "ALL=(root) NOPASSWD: /usr/local/sbin/ostia-loopmount" in doc
    assert "visudo -f /etc/sudoers.d/ostia" in doc
