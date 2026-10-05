"""pytest plugin: every test proves requirements named with `@pytest.mark.req("ID", ...)`.

When collection finishes, each test must carry at least one `req` marker whose ids all exist in the
requirements registry (`requirements.yaml`, ini option `req_registry`); otherwise the run is refused before
any test runs. The plugin only reads the collected tests, it never adds or removes one. The ids are recorded
in the JUnit report as a `req` property (sorted, comma-separated) for the traceability matrix.

Loaded with `-p tools.traceability.pytest_plugin` (see pyproject.toml).
"""

from pathlib import Path

import pytest
import yaml


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addini(
        "req_registry", "requirements registry (requirements.yaml)", default="requirements.yaml"
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "req(*ids): requirement ids proven by the test (FR-06, NFR-09, TOOLING, ...)"
    )


def registry_ids(config: pytest.Config) -> set[str]:
    path = Path(str(config.getini("req_registry")))
    if not path.is_absolute():
        path = config.rootpath / path
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        return {str(entry["id"]) for entry in document["requirements"]}
    except (OSError, yaml.YAMLError, KeyError, TypeError) as exc:
        raise pytest.UsageError(f"cannot read the requirements registry {path}: {exc}") from exc


def requirement_ids(item: pytest.Item, known: set[str], problems: list[str]) -> list[str]:
    """The requirement ids of a test; problems found are appended to `problems`."""
    markers = list(item.iter_markers("req"))
    if not markers:
        problems.append(f"{item.nodeid}: has no req marker")
        return []
    ids: list[str] = []
    for marker in markers:
        if not marker.args:
            problems.append(f"{item.nodeid}: req marker without an id")
        for value in marker.args:
            if not isinstance(value, str):
                problems.append(f"{item.nodeid}: requirement ids must be strings, got {value!r}")
            elif value not in known:
                problems.append(f"{item.nodeid}: unknown requirement id {value!r}")
            else:
                ids.append(value)
    return ids


def pytest_collection_finish(session: pytest.Session) -> None:
    known = registry_ids(session.config)
    problems: list[str] = []
    for item in session.items:
        ids = requirement_ids(item, known, problems)
        if ids:
            item.user_properties.append(("req", ",".join(sorted(set(ids)))))
    if problems:
        raise pytest.UsageError("requirement tags refused:\n" + "\n".join(problems))
