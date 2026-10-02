"""CI runs `just check` on a Debian image (NFR-15) and applies the acceptance and no-skip policies.

The workflow is checked as text: the project has no YAML parser dependency and the checks are structural.
"""

import re

import pytest

from tooling_support import REPO

CI = REPO / ".github" / "workflows" / "ci.yml"


def workflow() -> str:
    assert CI.is_file(), ".github/workflows/ci.yml is missing"
    return CI.read_text()


@pytest.mark.req("NFR-15")
def test_workflow_and_job_are_named_ci() -> None:
    text = workflow()
    assert re.search(r"^name: ci$", text, re.MULTILINE)
    assert re.search(r"^jobs:\n(?:.*\n)*?  ci:$", text, re.MULTILINE)


@pytest.mark.req("NFR-15")
def test_ci_job_runs_in_a_debian_stable_container() -> None:
    assert re.search(r"^    container:\n      image: debian:13[\w.-]*$", workflow(), re.MULTILINE)


@pytest.mark.req("NFR-15")
def test_ci_job_runs_just_check() -> None:
    assert re.search(r"^\s+run: just check$", workflow(), re.MULTILINE)


@pytest.mark.req("TOOLING")
def test_closed_phases_gate_and_current_phase_is_informational() -> None:
    text = workflow()
    assert "tools/ci/acceptance_plan.py" in text
    assert "ostia_lock.py gate" in text
    assert "just test-acceptance" in text
    assert text.count("continue-on-error: true") == 1


@pytest.mark.req("TOOLING")
def test_workflow_never_bypasses_hooks_or_rails() -> None:
    text = workflow()
    assert "--no-verify" not in text
    assert "rails.yml" not in text
