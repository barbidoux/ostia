#!/usr/bin/env python3
"""PreToolUse guard for Edit, Write, MultiEdit and NotebookEdit.

Blocks (exit 2, reason on stderr):
  * edits to the rails: CLAUDE.md, AGENTS.md, .claude/**, prompts/**, tools/lock/**,
    tools/kit/**, docs/spec.md, docs/plan.md, docs/unsafe-allowlist.md,
    .github/CODEOWNERS, .github/workflows/rails.yml, any LOCK.sha256,
    tests/acceptance/LOCKLOG.md;
  * edits to any file in a locked acceptance directory (tests/acceptance/<d>/ holding LOCK.sha256);
  * modifications of owner-gated files once they exist (deny.toml) outside their own work package;
  * any edit that ADDS a test-weakening construct (skip, ignore, xfail, focus, deselection);
  * any edit that ADDS `unsafe` in Rust outside crates listed in docs/unsafe-allowlist.md.

Asks the owner (permissionDecision "ask") when an edit:
  * adds a lint, type or coverage suppression, or relaxes a threshold;
  * touches a lever that decides which tests run (pytest ini keys, required-features, cfg(feature="bench"),
    should_panic, the bench marker, pytest run hooks, Playwright/Vitest filters, continue-on-error,
    .cargo/config);
  * removes tests or assertions (fewer test functions or assertions than before);
  * adds an owner-only command to a script, recipe or workflow (git tag, --no-verify, lock commands...).

Fails closed: an unexpected error blocks the edit.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

PROTECTED_EXACT = {
    "CLAUDE.md",
    "GUIDE-FR.md",
    "AGENTS.md",
    "docs/spec.md",
    "docs/plan.md",
    "docs/unsafe-allowlist.md",
    ".github/CODEOWNERS",
    ".github/workflows/rails.yml",
    "tests/acceptance/LOCKLOG.md",
}
PROTECTED_PREFIXES = (".claude/", "prompts/", "tools/lock/", "tools/kit/")
# file -> branch prefix on which it may still be modified after creation
OWNER_GATED = {"deny.toml": "wp/0.8-"}

NON_CODE_SUFFIXES = {".md", ".markdown", ".rst", ".txt", ".adoc"}

RS = {".rs"}
PY = {".py", ".pyi"}
JS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".svelte", ".vue"}
CONF = {".toml", ".cfg", ".ini", ".yml", ".yaml", ".json"}
ANY = None  # every non-documentation file, including justfile and Makefile

# (regex, label, suffixes it applies to)
WEAKENING = [
    (r"#\s*\[\s*ignore\b", "Rust #[ignore]", RS),
    (r"cfg_attr\(.*\bignore\b", "Rust cfg_attr(..., ignore)", RS),
    (r"#\s*\[\s*cfg\s*\(\s*any\s*\(\s*\)\s*\)", "Rust #[cfg(any())] (compiles code out)", RS),
    (r"#\s*\[\s*cfg\s*\(\s*all\s*\(\s*\)\s*\)", "Rust #[cfg(all())] trick", RS),
    (
        r"#\s*\[\s*cfg\s*\(\s*FALSE|#\s*\[\s*cfg\s*\(\s*never\b|#\s*\[\s*cfg\s*\(\s*disabled\b",
        "Rust cfg on an undefined flag",
        RS,
    ),
    (r"\bmark\.(?:skip|skipif|xfail)\b", "pytest skip/xfail marker", PY),
    (r"\bpytest\.(?:skip|xfail|importorskip|exit)\s*\(", "pytest.skip/xfail/importorskip/exit call", PY),
    (r"\bfrom\s+pytest\s+import\s+[^\n]*\b(?:skip|xfail|importorskip)\b", "importing pytest skip/xfail", PY),
    (r"getattr\(\s*pytest\b", "dynamic pytest attribute access", PY),
    (r"pytestmark\s*=.*\b(?:skip|skipif|xfail)\b", "module-level pytest skip", PY),
    (r"@unittest\.(?:skip|skipIf|skipUnless|expectedFailure)\b", "unittest skip/expectedFailure", PY),
    (r"\bexpectedFailure\b|\bSkipTest\b", "expectedFailure/SkipTest", PY),
    (r"parametrize\(\s*[^,()]+,\s*(?:\[\s*\]|\(\s*\))\s*[,)]", "empty parametrize (silently skipped)", PY),
    (r"\bpytest_collection_modifyitems\b", "pytest collection hook (deselection)", PY),
    (r"\bpytest_ignore_collect\b", "pytest ignore-collect hook", PY),
    (r"\bcollect_ignore(?:_glob)?\b", "pytest collect_ignore", PY),
    (r"--deselect\b", "pytest --deselect", ANY),
    (r"--ignore(?:-glob)?[= ]\S*tests", "pytest --ignore on tests", ANY),
    (r"-p\s+no:(?!cacheprovider)\w+", "disabling a pytest plugin", ANY),
    (r"\b(?:it|test|describe)\.(?:skip|todo|fixme|only)\s*\(", "JS/TS skip/todo/fixme/only", JS),
    (r"\bx(?:it|test|describe)\s*\(", "JS/TS xit/xtest/xdescribe", JS),
    (r"(?<![.\w])f(?:it|describe)\s*\(", "JS/TS focused test", JS),
    (r"\btest\.fail\s*\(", "Playwright test.fail", JS),
]

TEST_LEVERS = [
    (r"\bmark\.bench\b", "the `bench` marker (hardware-only tests; CI does not run them)", PY),
    (
        r"\b(?:addopts|testpaths|python_files|python_functions|python_classes|norecursedirs|confcutdir)\s*=",
        "pytest collection/run settings",
        CONF | PY,
    ),
    (
        r"\bpytest_(?:runtest_\w+|pyfunc_call|report_teststatus|make_collect_report|collectreport|sessionfinish)\b|"
        r"\bhookwrapper\b|\bwrapper\s*=\s*True",
        "pytest hooks that can change outcomes",
        PY,
    ),
    (r"#\s*\[\s*should_panic", "Rust #[should_panic]", RS),
    (r"#\s*\[\s*cfg\s*\((?:[^\]]*)feature\s*=\s*\"bench\"", 'Rust cfg(feature = "bench")', RS),
    (r"\brequired-features\b", "Cargo required-features (target not built by default)", CONF),
    (r"\bcontinue-on-error\b", "CI step allowed to fail", CONF),
    (r"\[\s*alias\s*\]", "cargo alias", CONF),
]

OWNER_ONLY_CONTENT = [
    (r"\bgit\s+tag\b", "git tag"),
    (r"--no-verify\b", "--no-verify"),
    (r"hooksPath", "core.hooksPath"),
    (r"ostia_lock(?:\.py)?[\"',\s]+(?:lock|relock|rails-update)\b", "lock/relock/rails-update"),
    (r"\bjust\s+(?:lock|relock|rails-update)\b", "just lock/relock/rails-update"),
    (r"\bgit\s+push\b[^\n]*(?:--force|\s-f\b|\s\+\S)", "force push"),
    (r"\bSKIP\s*=|PYTEST_ADDOPTS|PYTEST_PLUGINS", "gate-bypassing environment variable"),
    (r"\bgh\s+(?:pr\s+merge|release)\b", "gh merge/release"),
]

SUPPRESSIONS = [
    (r"#\s*pragma:\s*no\s*(?:cover|branch)", "coverage exclusion", PY),
    (r"#\s*\[\s*coverage\s*\(\s*off", "Rust coverage(off)", RS),
    (r"(?:istanbul|c8|v8)\s+ignore", "JS coverage ignore", JS),
    (r"#\s*type:\s*ignore", "mypy type: ignore", PY),
    (r"#\s*noqa\b", "ruff noqa", PY),
    (r"#!?\s*\[\s*allow\s*\(", "Rust #[allow(...)]", RS),
    (r"#!?\s*\[\s*expect\s*\(", "Rust #[expect(...)]", RS),
    (r"eslint-disable", "eslint-disable", JS),
    (r"@ts-(?:ignore|expect-error|nocheck)", "TypeScript suppression", JS),
    # configuration-level weakening of linters, type checkers and coverage
    (r"\bomit\s*=", "coverage omit", CONF),
    (r"\bexclude_(?:lines|also)\s*=", "coverage exclusion", CONF),
    (r"\bignore_errors\s*=\s*true", "mypy ignore_errors", CONF),
    (r"\bignore_missing_imports\s*=\s*true", "mypy ignore_missing_imports", CONF),
    (r"\bper-file-ignores\b", "ruff per-file-ignores", CONF),
    (r"\b(?:extend-)?ignore\s*=\s*\[\s*[^\]\s]", "ruff ignore list", CONF),
    (r"\bstrict\s*=\s*false", "type-checker strictness off", CONF),
    (r"=\s*[\"']allow[\"']|level\s*=\s*[\"']allow[\"']", "Rust/clippy lint set to allow", CONF),
    (r"-A\s+clippy::|-A\s+warnings|--cap-lints|RUSTFLAGS[^\n]*-A\b", "lint relaxed on the command line", ANY),
]
# files where some of the patterns above are normal content
SUPPRESSION_EXEMPT = {"deny.toml"}

THRESHOLD = re.compile(
    r"(?:fail[_-]under|--cov-fail-under|minimum[_-]score|mutation[_-]threshold)\s*[=:]?\s*[\"']?(\d+(?:\.\d+)?)"
)

TEST_FILE = re.compile(
    r"(?:^|/)tests?/|(?:^|/)test_[^/]*\.py$|_test\.py$|\.(?:test|spec)\.[cm]?[jt]sx?$|(?:^|/)conftest\.py$|\.rs$"
)
COUNTERS = [
    (r"(?m)^\s*(?:async\s+)?def\s+test\w*\s*\(", "test functions", PY),
    (r"\bassert\b|\bpytest\.raises\b", "assertions", PY),
    (r"#\s*\[\s*(?:tokio::|async_std::)?test\b|\bproptest!\s*\{|#\s*\[\s*rstest\b", "test functions", RS),
    (r"\b(?:debug_)?assert(?:_eq|_ne|_matches)?!", "assertions", RS),
    (r"\b(?:it|test)\s*\(", "test cases", JS),
    (r"\bexpect\s*\(", "assertions", JS),
]

UNSAFE = re.compile(
    r"\bunsafe\s*(?:\{|fn\b|impl\b|trait\b|extern\b)|allow\s*\(\s*unsafe_code|unsafe_code\s*=\s*[\"'](?:allow|warn)"
)


def deny(reason: str) -> None:
    print(f"BLOCKED by Ostia rails (.claude/hooks/guard_files.py): {reason}", file=sys.stderr)
    sys.exit(2)


def ask(reason: str) -> None:
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": f"Ostia rails: {reason}. The owner must approve this change.",
        }
    }
    print(json.dumps(out))
    sys.exit(0)


def project_dir(payload: dict) -> Path:
    return Path(os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or os.getcwd()).resolve()


def rel_path(root: Path, file_path: str, cwd: str | None) -> str | None:
    p = Path(file_path)
    if not p.is_absolute():
        p = Path(cwd or root) / p
    # resolve symlinks and '..' so tricks like a/../CLAUDE.md are caught
    p = Path(os.path.realpath(p))
    try:
        return p.relative_to(root).as_posix()
    except ValueError:
        return None


def current_branch(root: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=root, capture_output=True, text=True, timeout=5
        )
        return out.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def locked_acceptance(root: Path, rel: str) -> str | None:
    parts = rel.split("/")
    if len(parts) >= 3 and parts[0] == "tests" and parts[1] == "acceptance":
        if (root / "tests" / "acceptance" / parts[2] / "LOCK.sha256").exists():
            return parts[2]
    return None


def texts(tool: str, ti: dict, abs_path: Path) -> tuple[str, str]:
    """Return (old, new) text for the region being changed."""
    if tool == "Edit":
        return ti.get("old_string", "") or "", ti.get("new_string", "") or ""
    if tool == "MultiEdit":
        edits = ti.get("edits") or []
        return (
            "\n".join(e.get("old_string", "") or "" for e in edits),
            "\n".join(e.get("new_string", "") or "" for e in edits),
        )
    if tool == "Write":
        old = abs_path.read_text(encoding="utf-8", errors="replace") if abs_path.exists() else ""
        return old, ti.get("content", "") or ""
    if tool == "NotebookEdit":
        return "", ti.get("new_source", "") or ""
    return "", ""


def added(patterns, old: str, new: str, suffix: str) -> list[str]:
    found = []
    for rx, label, suffixes in patterns:
        if suffixes is not None and suffix not in suffixes:
            continue
        if len(re.findall(rx, new)) > len(re.findall(rx, old)):
            found.append(label)
    return found


def unsafe_allowed(root: Path, rel: str) -> bool:
    allow = root / "docs" / "unsafe-allowlist.md"
    if not allow.exists():
        return False
    crates = re.findall(r"(crates/[\w.-]+|workers/[\w.-]+)", allow.read_text(encoding="utf-8"))
    return any(rel == c or rel.startswith(c + "/") for c in crates)


def main() -> None:
    payload = json.load(sys.stdin)
    tool = payload.get("tool_name", "")
    ti = payload.get("tool_input") or {}
    file_path = ti.get("file_path") or ti.get("notebook_path")
    if not file_path:
        return
    root = project_dir(payload)
    rel = rel_path(root, file_path, payload.get("cwd"))
    if rel is None:
        return  # outside the repository: not our business
    abs_path = root / rel

    if (
        rel in PROTECTED_EXACT
        or rel.startswith(PROTECTED_PREFIXES)
        or rel.endswith("/LOCK.sha256")
        or rel == "LOCK.sha256"
    ):
        deny(f"{rel} is part of the rails and is owner-managed. If it must change, stop and ask the owner.")

    locked = locked_acceptance(root, rel)
    if locked:
        deny(
            f"tests/acceptance/{locked}/ is locked. Locked acceptance tests never change; "
            "if one looks wrong, stop and report it to the owner with the evidence."
        )

    if rel in OWNER_GATED and abs_path.exists() and not current_branch(root).startswith(OWNER_GATED[rel]):
        deny(f"{rel} is owner-gated once created (licence and source allowlist). Ask the owner to change it.")

    suffix = Path(rel).suffix.lower()
    if suffix in NON_CODE_SUFFIXES:
        return

    old, new = texts(tool, ti, abs_path)
    name = Path(rel).name

    weak = added(WEAKENING, old, new, suffix)
    if weak:
        deny(
            "this edit adds a test-weakening construct (" + ", ".join(weak) + "). Never skip, ignore, "
            "xfail, focus, deselect or compile out a test. A test that cannot pass is reported to the owner "
            "with the evidence; it is not disabled."
        )

    if suffix == ".rs" and len(UNSAFE.findall(new)) > len(UNSAFE.findall(old)) and not unsafe_allowed(root, rel):
        deny(
            "`unsafe` is not allowed outside the crates listed in docs/unsafe-allowlist.md. "
            "Find a safe alternative or ask the owner to allowlist the crate."
        )

    reasons: list[str] = []
    if rel.startswith(".cargo/") or "/.cargo/" in rel:
        reasons.append("cargo configuration (aliases, rustflags) can change what is built and tested")
    reasons += added(TEST_LEVERS, old, new, suffix)
    if re.search(r"(?:playwright|vitest|vite|jest)\.config\.", name):
        reasons += added(
            [
                (
                    r"\b(?:grepInvert|grep|testIgnore|testMatch|exclude|include|retries|bail)\s*:",
                    "Playwright/Vitest test selection settings",
                    None,
                )
            ],
            old,
            new,
            suffix,
        )
    if name not in SUPPRESSION_EXEMPT:
        reasons += added(SUPPRESSIONS, old, new, suffix)
    lowered = threshold_lowered(old, new)
    if lowered:
        reasons.append(lowered)
    if TEST_FILE.search(rel):
        reasons += removed(COUNTERS, old, new, suffix)
    owner_cmds = [label for rx, label in OWNER_ONLY_CONTENT if len(re.findall(rx, new)) > len(re.findall(rx, old))]
    if owner_cmds:
        reasons.append("it writes owner-only commands into a file (" + ", ".join(owner_cmds) + ")")
    if reasons:
        ask("this edit " + "; ".join(r if r.startswith("it ") else "adds or changes " + r for r in reasons))


def threshold_lowered(old: str, new: str) -> str | None:
    olds = [float(x) for x in THRESHOLD.findall(old)]
    news = [float(x) for x in THRESHOLD.findall(new)]
    if olds and news and min(news) < min(olds):
        return f"a lowered quality threshold ({min(olds):g} -> {min(news):g})"
    if olds and not news:
        return "a removed quality threshold"
    return None


def removed(patterns, old: str, new: str, suffix: str) -> list[str]:
    out = []
    for rx, label, suffixes in patterns:
        if suffixes is not None and suffix not in suffixes:
            continue
        before, after = len(re.findall(rx, old)), len(re.findall(rx, new))
        if after < before:
            out.append(f"removes {before - after} {label}")
    return [f"it {r}" for r in out]


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # fail closed
        print(f"BLOCKED: guard_files.py failed ({exc!r}); failing closed. Report this to the owner.", file=sys.stderr)
        sys.exit(2)
