"""CTR-04: the JSON contracts in schemas/ are versioned draft 2020-12 schemas, closed on every object, and
their examples validate (.claude/rules/contracts.md).
"""

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from tooling_support import REPO

SCHEMAS = REPO / "schemas"
EXAMPLES = SCHEMAS / "examples"
DRAFT = "https://json-schema.org/draft/2020-12/schema"
VERSIONED_ID = re.compile(
    r"^https://github\.com/barbidoux/ostia/schemas/[a-z-]+/v[0-9]+/[a-z-]+\.schema\.json$"
)
CONTRACT_SCHEMAS = ("report", "policy")


def schema_files() -> list[Path]:
    return sorted(SCHEMAS.glob("*.schema.json"))


def load(path: Path) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return document


def subschemas(node: object, where: str = "#") -> Iterator[tuple[str, dict[str, Any]]]:
    """Every schema that defines a value, with a JSON-pointer-like location. In-place applicators
    (`allOf`, `if`/`then`/`else`, `not`) only add conditions to a value their parent defines, so they
    are not walked."""
    if isinstance(node, dict):
        yield where, node
        for key, value in node.items():
            if key in ("properties", "$defs", "patternProperties"):
                for name, sub in value.items():
                    yield from subschemas(sub, f"{where}/{key}/{name}")
            elif key in ("items", "additionalProperties"):
                yield from subschemas(value, f"{where}/{key}")
            elif key in ("oneOf", "anyOf", "prefixItems"):
                for index, sub in enumerate(value):
                    yield from subschemas(sub, f"{where}/{key}/{index}")


def describes_object(schema: dict[str, Any]) -> bool:
    kind = schema.get("type")
    return (
        kind == "object" or (isinstance(kind, list) and "object" in kind) or "properties" in schema
    )


@pytest.mark.req("CTR-04")
def test_the_contract_schemas_exist() -> None:
    for name in CONTRACT_SCHEMAS:
        assert (SCHEMAS / f"{name}.schema.json").is_file(), f"schemas/{name}.schema.json is missing"
        assert (EXAMPLES / f"{name}.example.json").is_file(), (
            f"schemas/examples/{name}.example.json is missing"
        )


@pytest.mark.req("CTR-04")
@pytest.mark.parametrize("path", schema_files(), ids=lambda p: p.name)
def test_schemas_are_versioned_draft_2020_12(path: Path) -> None:
    schema = load(path)
    assert schema["$schema"] == DRAFT
    assert VERSIONED_ID.match(schema["$id"]), schema["$id"]
    jsonschema.Draft202012Validator.check_schema(schema)


@pytest.mark.req("CTR-04")
@pytest.mark.parametrize("path", schema_files(), ids=lambda p: p.name)
def test_every_object_refuses_unknown_keys(path: Path) -> None:
    open_objects = [
        where
        for where, schema in subschemas(load(path))
        if describes_object(schema)
        and not (
            schema.get("additionalProperties") is False
            or isinstance(schema.get("additionalProperties"), dict)
        )
    ]
    assert open_objects == []


@pytest.mark.req("CTR-04")
@pytest.mark.parametrize("name", CONTRACT_SCHEMAS)
def test_examples_validate(name: str) -> None:
    schema = load(SCHEMAS / f"{name}.schema.json")
    jsonschema.Draft202012Validator(schema).validate(load(EXAMPLES / f"{name}.example.json"))


@pytest.mark.req("CTR-04")
def test_policy_contract_shows_the_example_file() -> None:
    text = (REPO / "docs" / "contracts" / "policy.md").read_text(encoding="utf-8")
    shown = re.search(r"## Example\n\n```json\n(.*?)```", text, re.DOTALL)
    assert shown, "docs/contracts/policy.md has no JSON example"
    assert json.loads(shown.group(1)) == load(EXAMPLES / "policy.example.json")
