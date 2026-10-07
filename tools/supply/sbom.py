"""Writes the CycloneDX SBOMs of what Ostia ships (NFR-11).

Usage: sbom.py --out target/sbom

- `rust/<crate>.cdx.json`: one SBOM per shipped crate (workspace members under `crates/`), from
  `cargo cyclonedx`. cargo-cyclonedx writes next to each member's Cargo.toml; the files are moved out
  (or removed, for test doubles such as `tests/fakes/*`) so the source tree stays clean.
- `python/ostia-python.cdx.json`: the Python runtime dependencies only (no dev or audit group), installed
  by `uv sync --frozen` from uv.lock (hashes checked) into a throwaway virtual environment, then read
  by `cyclonedx-py`.

Everything runs offline: `uv sync --frozen --offline` needs only the wheels that the project's own
`uv sync --frozen` cached (an offline `uv pip install` would also need PyPI's index pages); cargo runs
with CARGO_NET_OFFLINE from the registry cache filled by the build. cargo-cyclonedx has no `--locked`,
so `cargo metadata --locked` (full resolution, for the host platform) first proves that Cargo.lock is up
to date. The member directories receive the generated files for a moment (cargo-cyclonedx has no output
directory option).
The timestamp comes from SOURCE_DATE_EPOCH, set to the last commit's time when not given.
Exit codes: 0 written, 1 a step failed (its output on stderr).
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SHIPPED = REPO / "crates"


class StepError(Exception):
    """A generator step failed."""


def run(cmd: list[str], env: dict[str, str]) -> str:
    result = subprocess.run(cmd, cwd=REPO, env=env, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise StepError(f"{' '.join(cmd)} failed ({result.returncode}):\n{result.stderr}")
    return result.stdout


def environment() -> dict[str, str]:
    env = {**os.environ, "CARGO_TERM_COLOR": "never", "CARGO_NET_OFFLINE": "true"}
    if "SOURCE_DATE_EPOCH" not in env:
        env["SOURCE_DATE_EPOCH"] = run(["git", "log", "-1", "--format=%ct"], env).strip()
    return env


def rust(out: Path, env: dict[str, str]) -> None:
    # Full resolution with --locked: fails if Cargo.lock would change. Filtered to the host platform, the
    # one cargo-cyclonedx describes: crates of other platforms (r-efi) are never downloaded by the build,
    # so they are not in the offline cache.
    host = next(
        line.removeprefix("host: ")
        for line in run(["rustc", "-vV"], env).splitlines()
        if line.startswith("host: ")
    )
    metadata = json.loads(
        run(
            ["cargo", "metadata", "--format-version", "1", "--locked", "--filter-platform", host],
            env,
        )
    )
    members = [
        package
        for package in metadata["packages"]
        if package["id"] in set(metadata["workspace_members"])
    ]
    generated = [Path(p["manifest_path"]).parent / f"{p['name']}.cdx.json" for p in members]
    tracked = run(["git", "ls-files", "--", *map(str, generated)], env).strip()
    if tracked:
        raise StepError(f"cargo cyclonedx would overwrite tracked files:\n{tracked}")
    try:
        run(["cargo", "cyclonedx", "--format", "json", "--spec-version", "1.5", "--quiet"], env)
        for path in generated:
            if not path.is_file():
                raise StepError(f"cargo cyclonedx did not write {path}")
            if path.parent.is_relative_to(SHIPPED):
                shutil.move(path, out / path.name)
    finally:
        for path in generated:
            path.unlink(missing_ok=True)


def python(out: Path, env: dict[str, str]) -> None:
    cyclonedx = Path(sys.executable).parent / "cyclonedx-py"
    if not cyclonedx.is_file():
        raise StepError(f"{cyclonedx} is missing (uv group audit)")
    with tempfile.TemporaryDirectory(prefix="ostia-sbom-") as scratch:
        venv = Path(scratch) / "venv"
        # From uv.lock, which uv checks the hashes against, without the dev and audit groups.
        run(
            [
                "uv",
                "sync",
                "--frozen",
                "--offline",
                "--quiet",
                "--no-default-groups",
                "--no-install-project",
                "--python",
                sys.executable,
            ],
            {**env, "UV_PROJECT_ENVIRONMENT": str(venv)},
        )
        run(
            [
                str(cyclonedx),
                "environment",
                "--pyproject",
                str(REPO / "pyproject.toml"),
                "--output-reproducible",
                "--output-file",
                str(out / "ostia-python.cdx.json"),
                str(venv),
            ],
            env,
        )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="CycloneDX SBOMs of the shipped components")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        env = environment()
        for part, generate in (("rust", rust), ("python", python)):
            directory = args.out / part
            if directory.exists():
                shutil.rmtree(directory)
            directory.mkdir(parents=True)
            generate(directory, env)
    except (StepError, OSError) as error:
        print(f"sbom: {error}", file=sys.stderr)
        return 1
    print(f"SBOMs written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
