"""The dev container and CI build the same Debian x86-64 environment from the same lists (NFR-15).

`tools/dev/packages.txt` (Debian packages) and `tools/dev/versions.env` (tool versions) are the single
sources: the setup script, the dev container and both CI jobs read them instead of repeating them.
Comments are removed before matching, and ci.yml is parsed, so only commands count.
"""

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from tooling_support import REPO

DEV = REPO / "tools" / "dev"
DOCKERFILE = REPO / ".devcontainer" / "Dockerfile"
DEVCONTAINER = REPO / ".devcontainer" / "devcontainer.json"
CI = REPO / ".github" / "workflows" / "ci.yml"
INSTALL_PACKAGES = "sed -e 's/#.*//' -e '/^[[:space:]]*$/d'"


def read(path: Path) -> str:
    assert path.is_file(), f"{path.relative_to(REPO)} is missing"
    return path.read_text(encoding="utf-8")


def without_comments(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def versions() -> dict[str, str]:
    lines = read(DEV / "versions.env").splitlines()
    return dict(line.split("=", 1) for line in lines if "=" in line)


def job(name: str) -> dict[str, Any]:
    workflow = yaml.safe_load(read(CI))
    jobs: dict[str, dict[str, Any]] = workflow["jobs"]
    assert name in jobs, f"job {name!r} not found"
    return jobs[name]


def run_bodies(name: str) -> list[str]:
    return [step["run"] for step in job(name)["steps"] if "run" in step]


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
    entries = versions()
    assert set(entries) == {
        "UV_VERSION",
        "JUST_VERSION",
        "NEXTEST_VERSION",
        "NIGHTLY_TOOLCHAIN",
        "CARGO_FUZZ_VERSION",
        "CARGO_DENY_VERSION",
        "CARGO_AUDIT_VERSION",
        "CARGO_CYCLONEDX_VERSION",
    }
    for key, value in entries.items():
        if key == "NIGHTLY_TOOLCHAIN":
            assert re.fullmatch(r"nightly-\d{4}-\d{2}-\d{2}", value), value
        else:
            assert re.fullmatch(r"\d+\.\d+\.\d+", value), value


@pytest.mark.req("NFR-15")
def test_dev_container_is_debian_stable_x86_64_built_from_the_single_sources() -> None:
    dockerfile = without_comments(read(DOCKERFILE))
    assert re.search(r"^FROM --platform=linux/amd64 debian:13$", dockerfile, re.MULTILINE)
    copy = "COPY tools/dev/packages.txt tools/dev/versions.env rust-toolchain.toml /tmp/ostia/"
    assert copy in dockerfile
    assert f"{INSTALL_PACKAGES} /tmp/ostia/packages.txt" in dockerfile
    assert "| xargs apt-get install -y --no-install-recommends" in dockerfile
    assert ". /tmp/ostia/versions.env" in dockerfile
    assert "cd /tmp/ostia && rustup toolchain install" in dockerfile
    for variable in versions():
        assert f"${{{variable}}}" in dockerfile
    config = json.loads(read(DEVCONTAINER))
    assert config["build"] == {"dockerfile": "Dockerfile", "context": ".."}
    assert "--privileged" in config["runArgs"]


@pytest.mark.req("NFR-15")
@pytest.mark.parametrize("name", ["ci", "acceptance-current", "fuzz", "red-first"])
def test_ci_jobs_install_from_the_single_sources(name: str) -> None:
    bodies = "\n".join(run_bodies(name))
    assert f"{INSTALL_PACKAGES} tools/dev/packages.txt" in bodies
    assert "| xargs apt-get install -y --no-install-recommends" in bodies
    assert 'cat tools/dev/versions.env >> "$GITHUB_ENV"' in bodies
    assert "${UV_VERSION}" in bodies
    assert "${JUST_VERSION}" in bodies
    assert "rustup toolchain install" in bodies


@pytest.mark.req("NFR-15")
def test_ci_job_installs_the_pinned_nextest() -> None:
    assert "${NEXTEST_VERSION}" in "\n".join(run_bodies("ci"))


@pytest.mark.req("NFR-11")
@pytest.mark.parametrize(
    ("variable", "crate"),
    [
        ("CARGO_DENY_VERSION", "cargo-deny"),
        ("CARGO_AUDIT_VERSION", "cargo-audit"),
        ("CARGO_CYCLONEDX_VERSION", "cargo-cyclonedx"),
    ],
)
def test_ci_job_installs_the_pinned_supply_chain_tools(variable: str, crate: str) -> None:
    # `just check` runs `just audit` (Q-27), so the ci job needs the tools at their pinned versions.
    assert f'cargo install --locked "{crate}@${{{variable}}}"' in "\n".join(run_bodies("ci"))


@pytest.mark.req("NFR-15")
@pytest.mark.parametrize("path", [CI, DOCKERFILE, REPO / "docs" / "dev-setup.md"])
def test_pinned_versions_are_not_repeated(path: Path) -> None:
    text = read(path)
    for variable, value in versions().items():
        assert value not in text, f"{path.relative_to(REPO)} repeats {variable}={value}"


@pytest.mark.req("NFR-15")
@pytest.mark.parametrize("name", ["ci", "acceptance-current"])
def test_ci_jobs_run_debian_stable_x86_64_with_loop_devices(name: str) -> None:
    definition = job(name)
    assert definition["runs-on"] == "ubuntu-latest"
    assert definition["container"] == {"image": "debian:13", "options": "--privileged"}


@pytest.mark.req("NFR-15")
def test_setup_script_installs_the_package_list_and_the_helper() -> None:
    script = without_comments(read(DEV / "setup-debian.sh"))
    assert f'{INSTALL_PACKAGES} "$script_dir/packages.txt"' in script
    assert (
        'install -o root -g root -m 0755 "$script_dir/loopmount.sh" /usr/local/sbin/ostia-loopmount'
        in script
    )


@pytest.mark.req("NFR-15")
def test_dev_setup_documents_the_sudoers_line() -> None:
    doc = read(REPO / "docs" / "dev-setup.md")
    assert "ALL=(root) NOPASSWD: /usr/local/sbin/ostia-loopmount" in doc
    assert "visudo -f /etc/sudoers.d/ostia" in doc
