"""Helpers for the tooling tests: repository paths and throwaway Cargo workspaces.

A throwaway workspace copies the repository's `[workspace.lints]`, `[workspace.package]` edition and
`rust-toolchain.toml`, so a seeded sample is checked exactly as a crate of the real workspace would be.
"""

import subprocess
import tomllib
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]


def run(cmd: list[str], cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run a command, capturing text output; never raises on a non-zero exit."""
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, check=False)


def repo_cargo_manifest() -> dict[str, Any]:
    """The parsed root Cargo.toml; fails the calling test if the workspace is missing."""
    path = REPO / "Cargo.toml"
    assert path.is_file(), "root Cargo.toml is missing: no Cargo workspace yet"
    with path.open("rb") as f:
        return tomllib.load(f)


def _toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{k} = {_toml_value(v)}" for k, v in value.items()) + " }"
    raise TypeError(f"unsupported TOML value in [workspace.lints]: {value!r}")


def make_workspace(root: Path, lib_rs: str) -> Path:
    """Create a one-crate workspace under `root` with the repository lints; return its directory."""
    manifest = repo_cargo_manifest()
    workspace = manifest.get("workspace", {})
    lints = workspace.get("lints")
    assert lints, "root Cargo.toml has no [workspace.lints]"
    edition = workspace.get("package", {}).get("edition")
    assert edition, "root Cargo.toml has no [workspace.package] edition"
    toolchain = REPO / "rust-toolchain.toml"
    assert toolchain.is_file(), "rust-toolchain.toml is missing"

    lines = ["[workspace]", 'members = ["sample"]', 'resolver = "3"', ""]
    for tool, table in lints.items():
        lines.append(f"[workspace.lints.{tool}]")
        lines.extend(f"{name} = {_toml_value(value)}" for name, value in table.items())
        lines.append("")
    (root / "Cargo.toml").write_text("\n".join(lines))
    (root / "rust-toolchain.toml").write_text(toolchain.read_text())
    crate = root / "sample"
    (crate / "src").mkdir(parents=True)
    (crate / "Cargo.toml").write_text(
        f'[package]\nname = "sample"\nversion = "0.0.0"\nedition = "{edition}"\npublish = false\n\n'
        "[lints]\nworkspace = true\n"
    )
    (crate / "src" / "lib.rs").write_text(lib_rs)
    return root


def cargo(workspace: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run cargo in a throwaway workspace with its own target directory."""
    return run(["cargo", *args], cwd=workspace)
