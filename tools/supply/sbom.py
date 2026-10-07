"""Writes the CycloneDX SBOMs of what Ostia ships (NFR-11).

Usage: sbom.py --out target/sbom

- `rust/<crate>.cdx.json`: one SBOM per shipped crate (workspace members under `crates/`), from
  `cargo cyclonedx`. cargo-cyclonedx writes next to each member's Cargo.toml; the files are moved out
  (or removed, for test doubles such as `tests/fakes/*`) so the source tree stays clean.
- `python/ostia-python.cdx.json`: the Python runtime dependencies only (no dev or audit group), installed
  with verified hashes from `uv export` into a throwaway virtual environment, then read by `cyclonedx-py`.

Everything runs offline (`uv` from its cache, `cargo --locked` from the registry cache filled by the build).
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
    env = {**os.environ, "CARGO_TERM_COLOR": "never"}
    if "SOURCE_DATE_EPOCH" not in env:
        env["SOURCE_DATE_EPOCH"] = run(["git", "log", "-1", "--format=%ct"], env).strip()
    return env


def rust(out: Path, env: dict[str, str]) -> None:
    metadata = json.loads(
        run(["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"], env)
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
        requirements = Path(scratch) / "requirements.txt"
        venv = Path(scratch) / "venv"
        run(
            [
                "uv",
                "export",
                "--frozen",
                "--no-default-groups",
                "--no-emit-project",
                "--format",
                "requirements-txt",
                "--output-file",
                str(requirements),
            ],
            env,
        )
        run(["uv", "venv", "--offline", "--quiet", "--python", sys.executable, str(venv)], env)
        run(
            [
                "uv",
                "pip",
                "install",
                "--offline",
                "--quiet",
                "--require-hashes",
                "--python",
                str(venv / "bin" / "python"),
                "--requirement",
                str(requirements),
            ],
            env,
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
            shutil.rmtree(directory, ignore_errors=True)
            directory.mkdir(parents=True)
            generate(directory, env)
    except StepError as error:
        print(f"sbom: {error}", file=sys.stderr)
        return 1
    print(f"SBOMs written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
