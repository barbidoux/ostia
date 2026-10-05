"""Dependabot proposes monthly, grouped version updates for every locked dependency set.

There are four sets: the Cargo workspace at the root, the separate fuzz workspace (`fuzz/`, its own
Cargo.lock), the uv project at the root and the GitHub Actions of the workflows. Each set gets at most
one grouped pull request per month, and its commits pass the commit-msg hook as `build(deps): ...`.
"""

from typing import Any

import pytest
import yaml

from tooling_support import REPO

DEPENDABOT = REPO / ".github" / "dependabot.yml"
EXPECTED = (
    ("cargo", "/"),
    ("cargo", "/fuzz"),
    ("uv", "/"),
    ("github-actions", "/"),
)


def config() -> dict[str, Any]:
    assert DEPENDABOT.is_file(), ".github/dependabot.yml is missing"
    loaded = yaml.safe_load(DEPENDABOT.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict), ".github/dependabot.yml is not a mapping"
    return loaded


def update(ecosystem: str, directory: str) -> dict[str, Any]:
    entries = [
        entry
        for entry in config().get("updates", [])
        if entry.get("package-ecosystem") == ecosystem and entry.get("directory") == directory
    ]
    assert len(entries) == 1, (
        f"expected one {ecosystem} update in {directory}, found {len(entries)}"
    )
    entry: dict[str, Any] = entries[0]
    return entry


@pytest.mark.req("TOOLING")
def test_dependabot_config_is_version_2() -> None:
    assert config().get("version") == 2


@pytest.mark.req("TOOLING")
def test_every_locked_dependency_set_has_exactly_one_update_entry() -> None:
    present = sorted(
        (entry.get("package-ecosystem"), entry.get("directory"))
        for entry in config().get("updates", [])
    )
    assert present == sorted(EXPECTED)


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(("ecosystem", "directory"), EXPECTED)
def test_updates_are_monthly(ecosystem: str, directory: str) -> None:
    assert update(ecosystem, directory).get("schedule", {}).get("interval") == "monthly"


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(("ecosystem", "directory"), EXPECTED)
def test_all_updates_of_an_ecosystem_are_grouped_into_one_pull_request(
    ecosystem: str, directory: str
) -> None:
    groups = update(ecosystem, directory).get("groups")
    assert isinstance(groups, dict) and len(groups) == 1, f"{ecosystem} {directory}: one group"
    (group,) = groups.values()
    assert group.get("patterns") == ["*"], f"{ecosystem} {directory}: the group must match all"
    # Any narrowing key would leave some updates outside the group, in pull requests of their own.
    for narrowing in ("exclude-patterns", "update-types", "dependency-type"):
        assert narrowing not in group, f"{ecosystem} {directory}: group narrowed by {narrowing}"


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(("ecosystem", "directory"), EXPECTED)
def test_open_pull_requests_are_limited_to_two(ecosystem: str, directory: str) -> None:
    limit = update(ecosystem, directory).get("open-pull-requests-limit")
    assert isinstance(limit, int) and 0 < limit <= 2, f"{ecosystem} {directory}: limit {limit!r}"


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(("ecosystem", "directory"), EXPECTED)
def test_commits_read_build_deps(ecosystem: str, directory: str) -> None:
    message = update(ecosystem, directory).get("commit-message", {})
    assert message.get("prefix") == "build"
    assert message.get("include") == "scope"
    assert "prefix-development" not in message, "development updates would get another prefix"
