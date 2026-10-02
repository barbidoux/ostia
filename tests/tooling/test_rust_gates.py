"""The Rust gates reject seeded bad samples and accept their clean twins.

NFR-09: unsafe code is forbidden in every crate of the workspace except the owner's allowlist.
TOOLING: clippy (pedantic, warnings denied), rustfmt and the toolchain pin.
"""

import tomllib
from pathlib import Path

import pytest

from tooling_support import REPO, cargo, make_workspace, repo_cargo_manifest

CLEAN_LIB = """//! Clean sample crate.

/// Length of a byte slice.
#[must_use]
pub fn length(bytes: &[u8]) -> usize {
    bytes.len()
}
"""

UNSAFE_LIB = """//! Sample crate with an unsafe block.

/// Reads one byte through a raw pointer.
#[must_use]
pub fn read(pointer: *const u8) -> u8 {
    unsafe { *pointer }
}
"""

# `forbid` (not `deny`): a local allow must not be able to re-enable unsafe code.
UNSAFE_WITH_LOCAL_ALLOW_LIB = """//! Sample crate trying to re-allow unsafe code locally.
#![allow(unsafe_code)]

/// Reads one byte through a raw pointer.
#[must_use]
pub fn read(pointer: *const u8) -> u8 {
    unsafe { *pointer }
}
"""

# clippy::cast_possible_truncation is a pedantic lint: it fires only if the workspace enables pedantic.
TRUNCATING_CAST_LIB = """//! Sample crate with a truncating cast.

/// Truncates a 64-bit value.
#[must_use]
pub fn narrow(value: u64) -> u32 {
    value as u32
}
"""

BADLY_FORMATTED_LIB = """//! Badly formatted sample crate.

/// Length of a byte slice.
#[must_use]
pub fn length( bytes : &[u8] ) -> usize { bytes.len() }
"""


@pytest.mark.req("NFR-09")
def test_workspace_forbids_unsafe_code() -> None:
    lints = repo_cargo_manifest()["workspace"]["lints"]
    assert lints["rust"]["unsafe_code"] == "forbid"


@pytest.mark.req("NFR-09")
def test_clean_sample_compiles_with_workspace_lints(tmp_path: Path) -> None:
    result = cargo(make_workspace(tmp_path, CLEAN_LIB), "check", "--quiet")
    assert result.returncode == 0, result.stderr


@pytest.mark.req("NFR-09")
def test_seeded_unsafe_block_fails_to_compile(tmp_path: Path) -> None:
    result = cargo(make_workspace(tmp_path, UNSAFE_LIB), "check", "--quiet")
    assert result.returncode != 0
    assert "error: usage of an `unsafe` block" in result.stderr
    assert "-F unsafe-code" in result.stderr


@pytest.mark.req("NFR-09")
def test_local_allow_cannot_reenable_unsafe_code(tmp_path: Path) -> None:
    result = cargo(make_workspace(tmp_path, UNSAFE_WITH_LOCAL_ALLOW_LIB), "check", "--quiet")
    assert result.returncode != 0
    assert "E0453" in result.stderr


def unsafe_allowlist() -> set[str]:
    """Crate names listed by the owner in docs/unsafe-allowlist.md."""
    names = set()
    for line in (REPO / "docs" / "unsafe-allowlist.md").read_text().splitlines():
        if not line.startswith("|"):
            continue
        first = line.strip().strip("|").split("|")[0].strip()
        if first not in ("Crate", "(none yet)") and set(first) - {"-"}:
            names.add(first)
    return names


@pytest.mark.req("NFR-09")
def test_every_crate_is_a_workspace_member() -> None:
    members = repo_cargo_manifest()["workspace"]["members"]
    assert "crates/core-domain" in members
    for manifest in sorted((REPO / "crates").glob("*/Cargo.toml")):
        member = manifest.parent.relative_to(REPO).as_posix()
        assert member in members, f"{member} is outside the workspace and escapes its lints"


@pytest.mark.req("NFR-09")
def test_every_crate_not_allowlisted_inherits_workspace_lints() -> None:
    allowed = unsafe_allowlist()
    for manifest in sorted((REPO / "crates").glob("*/Cargo.toml")):
        with manifest.open("rb") as f:
            crate = tomllib.load(f)
        if crate["package"]["name"] in allowed:
            continue
        member = manifest.parent.relative_to(REPO).as_posix()
        assert crate.get("lints") == {"workspace": True}, f"{member} does not inherit the lints"


@pytest.mark.req("TOOLING")
def test_clippy_denies_seeded_pedantic_warning(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path, TRUNCATING_CAST_LIB)
    result = cargo(workspace, "clippy", "--quiet", "--", "-D", "warnings")
    assert result.returncode != 0
    assert "cast_possible_truncation" in result.stderr


@pytest.mark.req("TOOLING")
def test_clippy_accepts_clean_sample(tmp_path: Path) -> None:
    result = cargo(make_workspace(tmp_path, CLEAN_LIB), "clippy", "--quiet", "--", "-D", "warnings")
    assert result.returncode == 0, result.stderr


@pytest.mark.req("TOOLING")
def test_rustfmt_check_rejects_badly_formatted_sample(tmp_path: Path) -> None:
    result = cargo(make_workspace(tmp_path, BADLY_FORMATTED_LIB), "fmt", "--all", "--check")
    assert result.returncode == 1
    assert "pub fn length(bytes: &[u8]) -> usize {" in result.stdout


@pytest.mark.req("TOOLING")
def test_rustfmt_check_accepts_formatted_sample(tmp_path: Path) -> None:
    result = cargo(make_workspace(tmp_path, CLEAN_LIB), "fmt", "--all", "--check")
    assert result.returncode == 0, result.stdout


@pytest.mark.req("TOOLING")
def test_rust_toolchain_pins_an_exact_stable_version() -> None:
    path = REPO / "rust-toolchain.toml"
    assert path.is_file(), "rust-toolchain.toml is missing"
    with path.open("rb") as f:
        toolchain = tomllib.load(f)["toolchain"]
    channel = toolchain["channel"]
    parts = channel.split(".")
    assert len(parts) == 3 and all(p.isdigit() for p in parts), f"channel {channel!r} is not X.Y.Z"
    assert {"rustfmt", "clippy", "llvm-tools-preview"} <= set(toolchain["components"])
