"""The Python gates (ruff, ruff format, mypy) apply the project configuration from pyproject.toml.

Each seeded defect is caught only by a project setting, so these tests fail until the setting exists.
Each test also checks the clean twin, so a gate that rejects everything does not pass either.
"""

import sys
from pathlib import Path

import pytest

from tooling_support import REPO, run

PYPROJECT = str(REPO / "pyproject.toml")

CLEAN = '''"""Clean sample."""


def first(items: list[int] | None = None) -> list[int]:
    """Return the items, or an empty list."""
    return items or []
'''

# ANN001 (missing argument annotation) is not in ruff's default rule set: only the project selects it.
UNANNOTATED = '''"""Sample with an unannotated argument."""


def first(items) -> list[int]:
    """Return the items."""
    return list(items)
'''

BADLY_FORMATTED = '''"""Badly formatted sample."""
values = {  'a':1 }
'''

# A 95-character call: kept on one line with the project line length (100), split with ruff's default (88).
LINE_OF_95 = "total = compute(alpha_value, beta_value, gamma_value, delta_value, epsilon_value, zeta_value_x)\n"

# Untyped definitions are errors only under mypy's strict mode.
UNTYPED_DEF = '''"""Sample with an untyped function."""


def identity(value):
    """Return the value."""
    return value
'''


def write(directory: Path, text: str) -> Path:
    directory.mkdir(exist_ok=True)
    sample = directory / "sample.py"
    sample.write_text(text)
    return sample


def ruff(*args: str) -> tuple[int, str]:
    result = run([sys.executable, "-m", "ruff", *args, "--config", PYPROJECT, "--no-cache"], cwd=REPO)
    return result.returncode, result.stdout + result.stderr


def mypy(sample: Path, cache: Path) -> tuple[int, str]:
    cmd = [sys.executable, "-m", "mypy", "--config-file", PYPROJECT, "--cache-dir", str(cache), str(sample)]
    result = run(cmd, cwd=REPO)
    return result.returncode, result.stdout + result.stderr


@pytest.mark.req("TOOLING")
def test_ruff_rejects_unannotated_argument_and_accepts_clean_twin(tmp_path: Path) -> None:
    code, output = ruff("check", str(write(tmp_path / "bad", UNANNOTATED)))
    assert code == 1
    assert "ANN001" in output
    code, output = ruff("check", str(write(tmp_path / "clean", CLEAN)))
    assert code == 0, output


@pytest.mark.req("TOOLING")
def test_ruff_format_rejects_bad_layout_and_uses_project_line_length(tmp_path: Path) -> None:
    code, output = ruff("format", "--check", str(write(tmp_path / "bad", BADLY_FORMATTED)))
    assert code == 1
    assert "File would be reformatted" in output
    code, output = ruff("format", "--check", str(write(tmp_path / "long", LINE_OF_95)))
    assert code == 0, output


@pytest.mark.req("TOOLING")
def test_mypy_is_strict_from_project_config_and_accepts_typed_twin(tmp_path: Path) -> None:
    code, output = mypy(write(tmp_path / "bad", UNTYPED_DEF), tmp_path / "cache")
    assert code == 1
    assert "Function is missing a type annotation" in output
    code, output = mypy(write(tmp_path / "clean", CLEAN), tmp_path / "cache")
    assert code == 0, output
