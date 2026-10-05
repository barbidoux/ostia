"""CI runs `just check` on a Debian image (NFR-15) and applies the acceptance and no-skip policies.

The workflow is checked as text: the project has no YAML parser dependency. Each assertion is scoped
to the block of the job it concerns (from `  <job>:` to the next two-space key).
"""

import re

import pytest

from tooling_support import REPO

CI = REPO / ".github" / "workflows" / "ci.yml"
WORKFLOWS = REPO / ".github" / "workflows"
# rails.yml is owner-managed (a rails file): its actions are pinned by the owner, not here.
OWNER_MANAGED = {"rails.yml"}
# A third-party action is pinned to a full commit SHA, with the release it corresponds to.
PINNED = r"@[0-9a-f]{40} # v\d+\.\d+\.\d+$"


def workflow() -> str:
    assert CI.is_file(), ".github/workflows/ci.yml is missing"
    return CI.read_text()


def job(name: str) -> str:
    match = re.search(rf"^  {re.escape(name)}:\n((?:(?!  \S).*\n|\n)*)", workflow(), re.MULTILINE)
    assert match, f"job {name!r} not found"
    return match.group(1)


def step(job_text: str, name: str) -> str:
    match = re.search(
        rf"^      - name: {re.escape(name)}\n((?:(?!      - ).*\n)*)", job_text, re.MULTILINE
    )
    assert match, f"step {name!r} not found"
    return match.group(1)


@pytest.mark.req("NFR-15")
def test_workflow_and_job_are_named_ci() -> None:
    assert re.search(r"^name: ci$", workflow(), re.MULTILINE)
    job("ci")


@pytest.mark.req("NFR-15")
def test_ci_job_runs_in_a_debian_stable_container() -> None:
    assert re.search(r"^    container:\n      image: debian:13[\w.-]*$", job("ci"), re.MULTILINE)


@pytest.mark.req("NFR-15")
def test_ci_job_runs_just_check_unconditionally() -> None:
    ci = job("ci")
    check = step(ci, "Check")
    assert check.strip() == "run: just check"
    assert "continue-on-error" not in ci
    assert not re.search(r"^\s+if:", ci, re.MULTILINE)


@pytest.mark.req("TOOLING")
def test_cached_tools_keep_their_executables() -> None:
    for name in ("ci", "acceptance-current"):
        cache = step(job(name), "Cache toolchains and builds")
        assert "~/.local/bin" in cache, f"{name}: uv tool executables are not cached"
        assert "~/.cargo/bin" in cache, f"{name}: cargo executables are not cached"


@pytest.mark.req("TOOLING")
def test_toolchain_comes_from_rust_toolchain_file() -> None:
    for name in ("ci", "acceptance-current"):
        assert "rustup toolchain install\n" in job(name)
        assert "rustup show active-toolchain ||" not in job(name)


@pytest.mark.req("TOOLING")
def test_closed_phases_gate_on_a_fresh_build() -> None:
    gate = step(job("ci"), "Acceptance gates (closed phases, blocking)")
    assert "tools/ci/acceptance_plan.py" in gate
    assert "python3 tools/lock/ostia_lock.py gate" in gate
    assert gate.index("cargo build --workspace --locked") < gate.index("ostia_lock.py gate")


@pytest.mark.req("TOOLING")
def test_current_phase_is_the_only_informational_job() -> None:
    assert workflow().count("continue-on-error: true") == 1
    current = job("acceptance-current")
    assert "    continue-on-error: true\n" in current
    acceptance = step(current, "Current phase acceptance (N/M green)")
    assert "just test-acceptance" in acceptance
    assert acceptance.index("cargo build --workspace --locked") < acceptance.index("for dir in")


@pytest.mark.req("TOOLING")
def test_workflow_never_bypasses_hooks_or_rails() -> None:
    text = workflow()
    assert "--no-verify" not in text
    assert "rails.yml" not in text


@pytest.mark.req("TOOLING")
def test_every_action_is_pinned_to_a_commit_sha_with_its_release() -> None:
    checked = 0
    for path in sorted(WORKFLOWS.glob("*.yml")):
        if path.name in OWNER_MANAGED:
            continue
        for line in path.read_text().splitlines():
            if not re.match(r"^\s*(?:- )?uses:", line):
                continue
            checked += 1
            assert re.match(rf"^\s*(?:- )?uses: [\w.-]+/[\w./-]+{PINNED}", line), (
                f"{path.name}: action not pinned to a commit SHA with a # vX.Y.Z comment: "
                f"{line.strip()}"
            )
    assert checked >= 6, f"only {checked} actions found in the workflows"


NIGHTLY = REPO / ".github" / "workflows" / "fuzz-nightly.yml"
FUZZ_TOOLS = (
    'rustup toolchain install "${NIGHTLY_TOOLCHAIN}" --profile minimal',
    'cargo install --locked "cargo-fuzz@${CARGO_FUZZ_VERSION}"',
)


@pytest.mark.req("NFR-06")
def test_every_push_and_pull_request_fuzzes_the_frame_decoder_for_a_fixed_time() -> None:
    fuzz = job("fuzz")
    assert '      FUZZ_SECONDS: "60"\n' in fuzz
    assert "    timeout-minutes: 30\n" in fuzz
    for line in FUZZ_TOOLS:
        assert line in fuzz, f"fuzz job: missing {line!r}"
    run = step(fuzz, "Fuzz suite (frame decoder for FUZZ_SECONDS, planted crash caught)")
    assert run.strip() == "run: just test-fuzz"
    assert "continue-on-error" not in fuzz
    assert not re.search(r"^\s+if:", fuzz, re.MULTILINE)


@pytest.mark.req("NFR-06")
def test_a_nightly_run_fuzzes_longer_on_a_cached_corpus() -> None:
    assert NIGHTLY.is_file(), ".github/workflows/fuzz-nightly.yml is missing"
    text = NIGHTLY.read_text()
    assert re.search(r"^  schedule:\n    - cron: \"0 2 \* \* \*\"$", text, re.MULTILINE)
    assert "  workflow_dispatch:\n" in text
    assert '      FUZZ_SECONDS: "1800"\n' in text
    assert "      FUZZ_CORPUS: fuzz/corpus/frame_decoder\n" in text
    for line in FUZZ_TOOLS:
        assert line in text, f"nightly: missing {line!r}"
    assert re.search(rf"^        uses: actions/cache{PINNED}", text, re.MULTILINE)
    assert "path: fuzz/corpus" in text
    assert "run: just test-fuzz" in text
    assert "continue-on-error" not in text
    assert "    timeout-minutes: 60\n" in text
    assert "    container:\n      image: debian:13\n" in text
    # A crash or timeout found at night is kept: libFuzzer writes it to FUZZ_ARTIFACTS, uploaded on failure.
    assert "      FUZZ_ARTIFACTS: fuzz/artifacts\n" in text
    upload = re.search(
        r"^      - name: Crash and timeout inputs\n"
        r"        if: failure\(\)\n"
        r"        uses: actions/upload-artifact@[0-9a-f]{40} # v\d+\.\d+\.\d+\n"
        r"        with:\n"
        r"          name: fuzz-artifacts\n"
        r"          path: fuzz/artifacts\n",
        text,
        re.MULTILINE,
    )
    assert upload, "nightly: no upload of fuzz/artifacts on failure"
    conditions = re.findall(r"^\s+if:", text, re.MULTILINE)
    assert len(conditions) == 1, "only the upload step is conditional"


@pytest.mark.req("NFR-15")
def test_the_fuzzing_toolchain_is_pinned() -> None:
    versions = (REPO / "tools" / "dev" / "versions.env").read_text().splitlines()
    assert "NIGHTLY_TOOLCHAIN=nightly-2026-10-04" in versions
    assert "CARGO_FUZZ_VERSION=0.13.2" in versions
