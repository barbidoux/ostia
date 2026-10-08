"""Configs of the fake engine (tests/fakes/fake_engine.py), passed to `ostia scan --dev-engine`."""

import json
from pathlib import Path
from typing import Any


def on_sha256(digest: str, **answer: object) -> dict[str, Any]:
    """A fake-engine rule answering `answer` (status, hint, score, findings, duration_ms) for the object
    with this SHA-256. `delay_ms`, `crash`, `signal` or `garbage` replace the answer when given."""
    rule: dict[str, Any] = {"match": {"sha256": digest}}
    for key in ("delay_ms", "crash", "signal", "garbage"):
        if key in answer:
            rule[key] = answer.pop(key)
    if not any(key in rule for key in ("crash", "signal", "garbage")):
        rule["respond"] = answer
    return rule


def fake_engine_config(
    directory: Path,
    engine_id: str,
    *,
    default: dict[str, Any] | None = None,
    rules: list[dict[str, Any]] | None = None,
    version: str = "1.0.0",
    content_version: str = "rules-1",
) -> Path:
    """Write the config of one fake engine; by default it answers OK with no opinion (hint NONE)."""
    config = {
        "engine": {"id": engine_id, "version": version, "content_version": content_version},
        "default": default if default is not None else {"status": "OK", "hint": "NONE"},
        "rules": rules or [],
    }
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"engine-{engine_id}.json"
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return path
