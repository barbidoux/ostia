"""Run pytest on test directories; an empty suite passes, a suite that collected nothing does not.

Usage: run_pytest.py <dir> [<dir> ...] -- [pytest arguments]
pytest exits with 5 when it collects no test. That counts as success only when the directories hold
no test file at all (a new, empty suite); if test files exist, exit 5 stands (everything deselected).
"""

import subprocess
import sys
from pathlib import Path

TEST_FILE_PATTERNS = ("test_*.py", "*_test.py")
JUNIT_OPTION = "--junitxml="
EMPTY_REPORT = '<?xml version="1.0" encoding="utf-8"?>\n<testsuites tests="0" />\n'


def write_empty_reports(pytest_args: list[str]) -> None:
    """Write the JUnit report pytest would have written, so report checks see this run."""
    for arg in pytest_args:
        if arg.startswith(JUNIT_OPTION):
            report = Path(arg.removeprefix(JUNIT_OPTION))
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(EMPTY_REPORT, encoding="utf-8")


def has_test_files(directories: list[Path]) -> bool:
    return any(
        next(directory.rglob(pattern), None) is not None
        for directory in directories
        for pattern in TEST_FILE_PATTERNS
    )


def main(argv: list[str]) -> int:
    if "--" in argv:
        split = argv.index("--")
        dirs, pytest_args = argv[:split], argv[split + 1 :]
    else:
        dirs, pytest_args = argv, []
    if not dirs:
        print("usage: run_pytest.py <dir> [<dir> ...] -- [pytest arguments]", file=sys.stderr)
        return 2
    directories = [Path(d) for d in dirs]
    for directory in directories:
        if not directory.is_dir():
            print(f"run_pytest: {directory} is not a directory", file=sys.stderr)
            return 2
    if not has_test_files(directories):
        print(f"run_pytest: no tests in {', '.join(dirs)}: empty suite passes")
        write_empty_reports(pytest_args)
        return 0
    cmd = [sys.executable, "-m", "pytest", *pytest_args, *dirs]
    return subprocess.run(cmd, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
