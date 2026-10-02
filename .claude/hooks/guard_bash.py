#!/usr/bin/env python3
"""PreToolUse guard for Bash commands.

Each command is split into segments (&&, ||, ;, |, newlines); wrappers such as `VAR=x`, `env`,
`command`, `sudo`, `timeout`, `uv run`, `uvx`, `npx`, `pnpm exec` are peeled off, and
`bash -c` / `sh -c` / `eval` strings are checked recursively. `cd`, `pushd` and `git -C` are
tracked so relative paths are resolved before they are checked.

Blocks (exit 2, reason on stderr):
  * history rewriting and gate bypass: force pushes (flags, +refspec, src:main, :ref deletion),
    push to main, --no-verify, git commit -n, git tag, update-ref, filter-branch/-repo, replace,
    core.hooksPath (config or -c), SKIP=/PRE_COMMIT_*/GIT_CONFIG*/PYTEST_ADDOPTS/PYTEST_PLUGINS
    and root-redirecting environment variables;
  * owner-only acts: just lock/relock/rails-update, ostia_lock.py lock/relock/rails-update,
    gh pr merge/review, gh release, package publishing;
  * shell writes to the rails or to locked acceptance tests;
  * shell writes to test files and test/CI/lint configuration (use the Edit/Write tools, which
    the file guard inspects);
  * contacting malware or threat-intelligence services with a network tool;
  * writing to real block devices; piping a download into a shell; removing top-level directories.
Asks the owner for: git commit --amend, git branch -f/-D, git reset --hard.

Fails closed: an unexpected error blocks the command.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import shlex
import subprocess
import sys
from pathlib import Path

# ----------------------------------------------------------------------------- path classes

RAILS = [
    r"^CLAUDE\.md$",
    r"^AGENTS\.md$",
    r"^GUIDE-FR\.md$",
    r"^\.claude(?:/|$)",
    r"^prompts(?:/|$)",
    r"^tools/lock(?:/|$)",
    r"^tools/kit(?:/|$)",
    r"^docs/spec\.md$",
    r"^docs/plan\.md$",
    r"^docs/unsafe-allowlist\.md$",
    r"^\.github/CODEOWNERS$",
    r"^\.github/workflows/rails\.yml$",
    r"(?:^|/)LOCK\.sha256$",
    r"^tests/acceptance/LOCKLOG\.md$",
]
# test files and the configuration that decides which tests run and how strictly
TEST_LEVERS = [
    r"(?:^|/)tests?/",
    r"(?:^|/)test_[^/]*\.py$",
    r"_test\.py$",
    r"\.(?:test|spec)\.[cm]?[jt]sx?$",
    r"(?:^|/)conftest\.py$",
    r"(?:^|/)pyproject\.toml$",
    r"(?:^|/)pytest\.ini$",
    r"(?:^|/)setup\.cfg$",
    r"(?:^|/)tox\.ini$",
    r"(?:^|/)Cargo\.toml$",
    r"(?:^|/)\.cargo/",
    r"(?:^|/)justfile$",
    r"\.just$",
    r"(?:^|/)\.github/workflows/",
    r"(?:^|/)playwright\.config",
    r"(?:^|/)vitest\.config",
    r"(?:^|/)\.pre-commit-config\.yaml$",
    r"(?:^|/)deny\.toml$",
    r"(?:^|/)fuzz/",
    r"(?:^|/)mutants\.toml$",
    r"(?:^|/)\.config/nextest\.toml$",
    r"(?:^|/)clippy\.toml$",
    r"(?:^|/)ruff\.toml$",
    r"(?:^|/)mypy\.ini$",
    r"^schemas/",  # contracts the acceptance tests rely on
]
SCRATCH = re.compile(
    r"(?:__pycache__|\.pyc$|(?:^|/)target/|\.pytest_cache|\.mypy_cache|\.ruff_cache|"
    r"node_modules|test-results|playwright-report|\.hypothesis|(?:^|/)\.wp-notes/|^/tmp/)"
)

MALWARE_HOSTS = [
    "virustotal.com",
    "bazaar.abuse.ch",
    "mb-api.abuse.ch",
    "urlhaus",
    "threatfox",
    "virusshare",
    "vx-underground",
    "vxug",
    "malshare",
    "thezoo",
    "dasmalwerk",
    "malwarebazaar",
    "hybrid-analysis.com",
    "any.run",
    "tria.ge",
    "malpedia",
]
NETWORK_TOOLS = re.compile(
    r"\b(?:curl|wget|xh|https?|aria2c|nc|ncat|socat|ftp|sftp|scp|rsync|git\s+clone|git\s+fetch|pip\s+download|"
    r"requests|urllib|httpx|aiohttp|gh\s+api|openssl\s+s_client)\b"
)
BLOCK_DEVICE = re.compile(
    r"/dev/(?:sd[a-z]+\d*|nvme\d+n\d+(?:p\d+)?|mmcblk\d+(?:p\d+)?|hd[a-z]+\d*|vd[a-z]+\d*|disk/by-)"
)
FORBIDDEN_ENV = re.compile(
    r"^(?:SKIP|PRE_COMMIT_\w*|GIT_CONFIG\w*|GIT_DIR|GIT_WORK_TREE|PYTEST_ADDOPTS|PYTEST_PLUGINS|"
    r"OSTIA_REPO_ROOT|CLAUDE_PROJECT_DIR)$"
)
WRAPPERS = {"sudo", "doas", "command", "exec", "nice", "nohup", "time", "stdbuf", "ionice", "env", "xargs", "builtin"}
RUNNERS = {"uv", "poetry", "pipenv", "pdm", "hatch", "rye"}
VALUE_OPTS = {
    "--with",
    "--python",
    "-p",
    "--project",
    "--directory",
    "--extra",
    "--group",
    "--env-file",
    "--package",
    "--from",
    "-n",
    "-u",
    "-g",
    "-C",
    "--chdir",
    "-s",
    "--signal",
    "-k",
    "--kill-after",
}

ASKS: list[str] = []


def deny(reason: str) -> None:
    print(f"BLOCKED by Ostia rails (.claude/hooks/guard_bash.py): {reason}", file=sys.stderr)
    sys.exit(2)


# ----------------------------------------------------------------------------- parsing helpers


def segments(cmd: str) -> list[str]:
    """Split on shell separators outside quotes (approximation good enough for a guard)."""
    out, buf, quote, i = [], [], None, 0
    while i < len(cmd):
        c = cmd[i]
        if quote:
            buf.append(c)
            if c == quote:
                quote = None
            elif c == "\\" and quote == '"' and i + 1 < len(cmd):
                buf.append(cmd[i + 1])
                i += 1
        elif c in ("'", '"'):
            quote = c
            buf.append(c)
        elif c in ";\n" or (c == "&" and cmd[i : i + 2] == "&&") or c == "|":
            if c == "&" or cmd[i : i + 2] == "||":
                i += 1
            out.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i += 1
    out.append("".join(buf))
    return [s.strip() for s in out if s.strip()]


def words(seg: str) -> list[str]:
    try:
        return shlex.split(seg, posix=True)
    except ValueError:
        return seg.split()


def peel(w: list[str]) -> tuple[list[str], list[str]]:
    """Remove env assignments and wrapper commands. Returns (words, recursive command strings)."""
    nested: list[str] = []
    changed = True
    while w and changed:
        changed = False
        head = w[0]
        m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)", head)
        if m:
            if FORBIDDEN_ENV.match(m.group(1)):
                deny(f"setting {m.group(1)} would bypass or redirect the gates.")
            w, changed = w[1:], True
            continue
        if head == "export":
            for a in w[1:]:
                name = a.split("=", 1)[0]
                if FORBIDDEN_ENV.match(name):
                    deny(f"exporting {name} would bypass or redirect the gates.")
            return [], nested
        if head in WRAPPERS or head == "timeout":
            w = w[1:]
            while w and (w[0].startswith("-") or re.fullmatch(r"[A-Za-z_]\w*=.*", w[0])):
                if re.fullmatch(r"([A-Za-z_]\w*)=.*", w[0]) and FORBIDDEN_ENV.match(w[0].split("=", 1)[0]):
                    deny(f"setting {w[0].split('=', 1)[0]} would bypass or redirect the gates.")
                w = w[2:] if w[0] in VALUE_OPTS and len(w) > 1 else w[1:]
            if head == "timeout" and w and re.fullmatch(r"[\d.]+[smhd]?", w[0]):
                w = w[1:]
            changed = True
            continue
        if head in RUNNERS and len(w) > 1 and w[1] in ("run", "exec"):
            w = w[2:]
            while w and w[0].startswith("-"):
                w = w[2:] if w[0] in VALUE_OPTS and len(w) > 1 else w[1:]
            changed = True
            continue
        if head in ("uvx", "npx", "pnpx", "bunx", "pipx"):
            w = w[1:] if head != "pipx" else w[2:]
            while w and w[0].startswith("-"):
                w = w[2:] if w[0] in VALUE_OPTS and len(w) > 1 else w[1:]
            changed = True
            continue
        if head in ("pnpm", "npm", "yarn", "bun") and len(w) > 1 and w[1] in ("exec", "dlx", "x"):
            w, changed = w[2:], True
            continue
        if head in ("bash", "sh", "zsh", "dash", "ksh") and "-c" in w:
            idx = w.index("-c")
            if idx + 1 < len(w):
                nested.append(w[idx + 1])
            return [], nested
        if head == "eval":
            nested.append(" ".join(w[1:]))
            return [], nested
    return w, nested


def norm(path: str, cwd: str) -> str:
    """Normalise a path relative to the repository root (cwd is relative to the root, '' = root)."""
    if path.startswith("~"):
        return path
    p = path if path.startswith("/") else posixpath.join(cwd, path) if cwd else path
    p = posixpath.normpath(p)
    root = ROOT.as_posix()
    if p.startswith(root + "/"):
        p = p[len(root) + 1 :]
    elif p == root:
        p = "."
    return p[2:] if p.startswith("./") else p


def is_rails(p: str) -> bool:
    if any(re.search(rx, p) for rx in RAILS):
        return True
    parts = p.split("/")
    if len(parts) >= 3 and parts[0] == "tests" and parts[1] == "acceptance":
        return (ROOT / "tests" / "acceptance" / parts[2] / "LOCK.sha256").exists()
    if p in ("tests/acceptance", "tests") and any((ROOT / "tests" / "acceptance").glob("*/LOCK.sha256")):
        return True
    return False


def is_test_lever(p: str) -> bool:
    return not SCRATCH.search(p) and any(re.search(rx, p) for rx in TEST_LEVERS)


def current_branch() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=ROOT, capture_output=True, text=True, timeout=5
        ).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


# ----------------------------------------------------------------------------- write targets

REDIRECT = re.compile(r"(?<![<0-9&])(?:\d?>>?|&>>?|>\|)\s*([^\s;&|<>]+)")


def write_targets(seg: str, w: list[str]) -> list[str]:
    targets = [t for t in REDIRECT.findall(seg) if t not in ("/dev/null", "&1", "&2")]
    if not w:
        return targets
    cmd, args = w[0], [a for a in w[1:]]
    plain = [a for a in args if not a.startswith("-")]
    if cmd in ("rm", "rmdir", "unlink", "truncate", "shred", "touch", "chmod", "chown", "chgrp", "ln", "mv", "mkfifo"):
        targets += plain
    elif cmd in ("cp", "install", "rsync") and plain:
        targets.append(plain[-1])
    elif cmd == "tee":
        targets += plain
    elif cmd in ("sed", "perl", "ruby") and any(re.fullmatch(r"-[a-zA-Z]*i.*|--in-place.*", a) for a in args):
        targets += plain[1:] if cmd == "sed" else plain
    elif cmd == "dd":
        targets += [a[3:] for a in args if a.startswith("of=")]
    elif cmd == "find" and any(a in ("-delete", "-exec", "-execdir", "-ok") for a in args):
        targets += [a for a in args[:1] if not a.startswith("-")] or ["."]
    elif cmd == "patch":
        targets += plain or ["."]
    elif cmd == "git" and len(args) >= 1:
        sub_i = 0
        while sub_i < len(args) and args[sub_i].startswith("-"):
            sub_i += 2 if args[sub_i] in ("-C", "-c") else 1
        sub = args[sub_i] if sub_i < len(args) else ""
        rest = args[sub_i + 1 :]
        if sub in ("rm", "mv", "restore", "apply", "am"):
            targets += [a for a in rest if not a.startswith("-")] or ["."]
        elif sub == "checkout" and "--" in rest:
            targets += rest[rest.index("--") + 1 :]
        elif sub == "stash" and rest[:1] in (["pop"], ["apply"]):
            targets.append(".")
    elif cmd in ("python", "python3") and "-c" in args:
        code = args[args.index("-c") + 1] if args.index("-c") + 1 < len(args) else ""
        targets += python_targets(code)
    return targets


PY_WRITES = re.compile(
    r"""open\([^)]*['"][wax+]|write_text|write_bytes|unlink|rename|replace\(|rmtree|remove\(|shutil|"""
    r"""os\.system|subprocess"""
)


def python_targets(code: str) -> list[str]:
    """Quoted strings of a Python snippet that writes files (approximation)."""
    if not PY_WRITES.search(code):
        return []
    return re.findall(r"""['"]([^'"\s]+)['"]""", code)


HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def split_heredocs(cmd: str) -> tuple[str, list[tuple[str, str]]]:
    """Remove heredoc bodies from the command; return them with the line that opened them."""
    lines, out, bodies, i = cmd.split("\n"), [], [], 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        for m in HEREDOC.finditer(line):
            body = []
            while i < len(lines) and lines[i].strip() != m.group(2):
                body.append(lines[i])
                i += 1
            i += 1
            bodies.append((line, "\n".join(body)))
    return "\n".join(out), bodies


# ----------------------------------------------------------------------------- checks


def check_git(w: list[str], cwd: str) -> str:
    """Returns the cwd implied by `git -C` for the rest of this segment."""
    if len(w) < 2 or w[0] != "git":
        return cwd
    i = 1
    while i < len(w) and w[i].startswith("-"):
        if w[i] == "-c" and i + 1 < len(w):
            if "hookspath" in w[i + 1].lower():
                deny("overriding core.hooksPath disables the commit gates.")
            i += 2
        elif w[i] == "-C" and i + 1 < len(w):
            cwd = norm(w[i + 1], cwd)
            i += 2
        else:
            i += 1
    if i >= len(w):
        return cwd
    sub, args = w[i], w[i + 1 :]
    if "--no-verify" in args:
        deny("--no-verify bypasses the pre-commit and pre-push gates. Fix the failure instead.")
    if sub == "commit":
        for a in args:
            if re.fullmatch(r"-[a-zA-Z]*n[a-zA-Z]*", a):
                deny("git commit -n bypasses the pre-commit gates (it means --no-verify).")
        if "--amend" in args:
            ASKS.append("git commit --amend rewrites a commit (the test-first commit history is evidence)")
    if sub == "push":
        if any(
            a in ("-f", "--force", "--force-with-lease", "--force-if-includes", "--mirror", "--delete", "-d", "--prune")
            or a.startswith("--force")
            or re.fullmatch(r"-[a-zA-Z]*f[a-zA-Z]*", a)
            for a in args
        ):
            deny("force-pushing or deleting remote refs rewrites history. Never do it.")
        for a in args:
            if a.startswith("+"):
                deny("a +refspec is a force push. Never do it.")
            if a.startswith(":"):
                deny("a ':<ref>' refspec deletes a remote ref. Never do it.")
            dst = a.split(":", 1)[1] if ":" in a else a
            if re.fullmatch(r"(?:HEAD:)?(?:refs/heads/)?(?:main|master)", dst) or re.fullmatch(
                r"(?:refs/heads/)?(?:main|master)", dst
            ):
                deny("never push to main; push your wp/<id>-<slug> branch and open a merge request.")
            if dst.startswith(("refs/tags/", "lock-")):
                deny("pushing tags is the owner's act.")
        if "--tags" in args or "--follow-tags" in args:
            deny("pushing tags is the owner's act.")
    if sub in ("tag", "update-ref", "filter-branch", "filter-repo", "replace"):
        deny(f"git {sub} is reserved for the owner (lock tags and history are part of the rails).")
    if sub == "config" and any("hookspath" in a.lower() for a in args):
        deny("changing core.hooksPath disables the commit gates.")
    if sub == "branch" and any(a in ("-f", "--force", "-D", "-M", "-C") for a in args):
        ASKS.append(f"git branch {' '.join(args)} moves or deletes a branch")
    if sub == "reset" and "--hard" in args:
        ASKS.append("git reset --hard discards work")
    return cwd


def check_owner_only(w: list[str]) -> None:
    if len(w) >= 2 and w[0] == "just" and w[1] in ("lock", "relock", "rails-update"):
        deny("locking tests and updating the rails manifest are the owner's acts. Ask the owner.")
    for idx, x in enumerate(w):
        if x.endswith("ostia_lock.py") and idx + 1 < len(w) and w[idx + 1] in ("lock", "relock", "rails-update"):
            deny("locking tests and updating the rails manifest are the owner's acts. Ask the owner.")
    if len(w) >= 3 and w[0] == "gh" and ((w[1] == "pr" and w[2] in ("merge", "review")) or w[1] == "release"):
        deny("merging, approving and releasing are the owner's acts.")
    if (
        len(w) >= 2
        and w[0] == "gh"
        and w[1] == "api"
        and any(re.search(r"/(?:merges?|git/refs|releases)\b", a) for a in w)
    ):
        deny("merging, moving refs and releasing through the API are the owner's acts.")
    if len(w) >= 2 and w[0] in ("cargo", "npm", "pnpm", "yarn", "uv", "twine", "poetry") and w[1] == "publish":
        deny("publishing packages is the owner's act.")


def check_devices(seg: str, w: list[str]) -> None:
    if not BLOCK_DEVICE.search(seg) or not w:
        return
    cmd, args = w[0], w[1:]
    writes = False
    if cmd == "dd":
        writes = any(a.startswith("of=") and BLOCK_DEVICE.search(a) for a in args)
    elif re.fullmatch(r"mkfs(?:\.\w+)?|mke2fs|mkntfs|mkexfatfs|mkfs\.exfat|wipefs|blkdiscard|shred|mkswap", cmd):
        writes = True
    elif cmd in ("fdisk", "sfdisk", "sgdisk", "parted", "gdisk", "cfdisk"):
        writes = not any(a in ("-l", "--list", "-p", "--print", "print", "-d", "--dump") for a in args)
    elif cmd == "badblocks":
        writes = any(a in ("-w", "-n") for a in args)
    elif cmd == "hdparm":
        writes = any(
            a.startswith(("--security", "--trim", "--yes-i-know", "-z", "--make-bad", "--write")) for a in args
        )
    if any(t for t in REDIRECT.findall(seg) if BLOCK_DEVICE.search(t)):
        writes = True
    if writes:
        deny(
            "writing to a real block device is forbidden. Use loop devices from the image generators, "
            "or the bench device named by OSTIA_BENCH_DEVICE through the owner-approved bench scripts."
        )


def check_command(cmd: str, depth: int = 0) -> None:
    if depth > 4:
        deny("command nesting too deep to inspect.")
    low = cmd.lower()
    for host in MALWARE_HOSTS:
        if re.search(r"(?<![\w-])" + re.escape(host), low) and NETWORK_TOOLS.search(low):
            deny(
                f"the shell must not contact {host}. Tests use recorded responses and generated samples; "
                "no real malware or live threat-intelligence calls, ever."
            )
    if re.search(r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b", cmd):
        deny("piping a download into a shell is not allowed. Download, inspect, pin by hash.")

    cmd, bodies = split_heredocs(cmd)
    for head, body in bodies:
        hw, _ = peel(words(head.split("<<")[0]))
        interp = Path(hw[0]).name if hw else ""
        if interp.startswith("python"):
            for t in python_targets(body):
                p = norm(t, "")
                if is_rails(p) or is_test_lever(p):
                    deny(
                        f"this script would modify {p}; rails and locked tests are owner-managed, and tests or "
                        "test configuration are changed with the Edit or Write tools only."
                    )
        elif interp in ("bash", "sh", "zsh", "dash", "ksh", "source", "."):
            check_command(body, depth + 1)

    cwd = ""
    for seg in segments(cmd):
        w, nested = peel(words(seg))
        for inner in nested:
            check_command(inner, depth + 1)
        if not w:
            continue
        if w[0] in ("cd", "pushd") and len(w) > 1:
            cwd = norm(w[1], cwd)
            continue
        seg_cwd = check_git(w, cwd)
        check_owner_only(w)
        check_devices(seg, w)
        if w[0] in ("rm", "mv") and any(
            norm(a, cwd) in (".", "tools", "tests", "docs", ".github", "/", "*", "crates")
            for a in w[1:]
            if not a.startswith("-")
        ):
            deny("removing or moving a top-level directory is not allowed.")
        for t in write_targets(seg, w):
            p = norm(t, seg_cwd)
            if is_rails(p):
                deny(
                    f"this command would modify {p}, a rails file or a locked acceptance test. These are "
                    "owner-managed: read them freely, never change them. If one looks wrong, tell the owner."
                )
            if p == "deny.toml" and (ROOT / "deny.toml").exists() and not current_branch().startswith("wp/0.8-"):
                deny("deny.toml is owner-gated once created. Propose the change to the owner.")
            if is_test_lever(p):
                deny(
                    f"modify {p} with the Edit or Write tools, not the shell, so the change can be inspected "
                    "(tests and test/lint/CI configuration)."
                )


def main() -> None:
    payload = json.load(sys.stdin)
    if payload.get("tool_name") != "Bash":
        return
    cmd = (payload.get("tool_input") or {}).get("command", "") or ""
    global ROOT
    ROOT = Path(os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or os.getcwd()).resolve()
    check_command(cmd)
    if ASKS:
        print(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "ask",
                        "permissionDecisionReason": "Ostia rails: " + "; ".join(ASKS) + ". The owner must approve.",
                    }
                }
            )
        )


ROOT = Path(".")

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # fail closed
        print(f"BLOCKED: guard_bash.py failed ({exc!r}); failing closed. Report this to the owner.", file=sys.stderr)
        sys.exit(2)
