"""FR-09 and ADR-09: verdicts come only from the signed policy. The signature (Ed25519, detached, over the
exact bytes) is checked before the content, and before the medium is opened; an unsigned, altered, foreign or
invalid policy is refused and nothing is scanned (docs/contracts/policy.md, docs/contracts/cli.md)."""

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from common import (
    SignedPolicy,
    blank_image,
    fake_engine_config,
    load_report,
    new_key,
    policy_document,
    run_ostia,
    sha256,
    write_signed_policy,
)

ENGINES = {"fake-av": {"role": "detector", "trusted_alone": False}}


def valid(work: Path) -> SignedPolicy:
    return write_signed_policy(work, policy_document(ENGINES, version="p1-signature"))


def altered(work: Path) -> SignedPolicy:
    # Still valid JSON after the change: only the signature can tell.
    signed = valid(work)
    signed.policy.write_bytes(signed.data.replace(b"p1-signature", b"p1-signaturf"))
    return signed


def foreign_key(work: Path) -> SignedPolicy:
    return write_signed_policy(work, policy_document(ENGINES), key=new_key(), trusted=new_key())


def truncated_signature(work: Path) -> SignedPolicy:
    signed = valid(work)
    signed.signature.write_bytes(signed.signature.read_bytes()[:63])
    return signed


def empty_signature(work: Path) -> SignedPolicy:
    signed = valid(work)
    signed.signature.write_bytes(b"")
    return signed


def short_trusted_key(work: Path) -> SignedPolicy:
    signed = valid(work)
    signed.trust.write_bytes(signed.trust.read_bytes()[:31])
    return signed


def signed_document(document: dict[str, Any] | bytes) -> Callable[[Path], SignedPolicy]:
    def make(work: Path) -> SignedPolicy:
        return write_signed_policy(work, document)

    return make


def with_changes(**changes: object) -> dict[str, Any]:
    document = policy_document(ENGINES)
    document.update(changes)
    return document


INVERTED = {"ember": {"role": "scorer", "thresholds": {"low": 0.9, "high": 0.5}}}
EQUAL = {"ember": {"role": "scorer", "thresholds": {"low": 0.7, "high": 0.7}}}


def without_limits() -> dict[str, Any]:
    document = policy_document(ENGINES)
    del document["limits"]
    return document


def nested(change: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    document = policy_document(ENGINES)
    change(document)
    return document


def drop_single_detection(document: dict[str, Any]) -> None:
    del document["rules"]["R6"]["single_detection"]


def add_nested_key(document: dict[str, Any]) -> None:
    document["rules"]["R6"]["extra"] = True


def k_of_one(document: dict[str, Any]) -> None:
    document["rules"]["R2"]["k"] = 1


def depth_zero(document: dict[str, Any]) -> None:
    document["limits"]["max_depth"] = 0


def timeout_zero(document: dict[str, Any]) -> None:
    document["limits"]["engine_timeout_seconds"] = 0


@dataclass(frozen=True)
class Refused:
    name: str
    make: Callable[[Path], SignedPolicy]
    code: str


REFUSED = [
    Refused("altered", altered, "policy_signature_invalid"),
    Refused("foreign-key", foreign_key, "policy_signature_invalid"),
    Refused("truncated-signature", truncated_signature, "policy_signature_invalid"),
    Refused("empty-signature", empty_signature, "policy_signature_invalid"),
    Refused("short-trusted-key", short_trusted_key, "policy_signature_invalid"),
    Refused("not-json", signed_document(b"version = 'not json'\n"), "policy_invalid"),
    Refused("unknown-key", signed_document(with_changes(extra=1)), "policy_invalid"),
    Refused(
        "other-schema", signed_document(with_changes(schema="ostia.policy.v2")), "policy_invalid"
    ),
    Refused(
        "inverted-thresholds",
        signed_document(with_changes(engines={**ENGINES, **INVERTED})),
        "policy_invalid",
    ),
    Refused(
        "equal-thresholds",
        signed_document(with_changes(engines={**ENGINES, **EQUAL})),
        "policy_invalid",
    ),
    Refused("missing-limits", signed_document(without_limits()), "policy_invalid"),
    Refused("missing-nested-key", signed_document(nested(drop_single_detection)), "policy_invalid"),
    Refused("unknown-nested-key", signed_document(nested(add_nested_key)), "policy_invalid"),
    Refused("k-of-one", signed_document(nested(k_of_one)), "policy_invalid"),
    Refused("depth-zero", signed_document(nested(depth_zero)), "policy_invalid"),
    Refused("timeout-zero", signed_document(nested(timeout_zero)), "policy_invalid"),
]


def name(case: Refused) -> str:
    return case.name


@pytest.mark.req("FR-09")
def test_valid_policy_verifies(tmp_path: Path) -> None:
    signed = valid(tmp_path)
    result = run_ostia("policy", "verify", *signed.args())
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"version": "p1-signature", "sha256": sha256(signed.data)}


@pytest.mark.req("FR-09")
@pytest.mark.parametrize("case", REFUSED, ids=name)
def test_refused_policy_does_not_verify(tmp_path: Path, case: Refused) -> None:
    result = run_ostia("policy", "verify", *case.make(tmp_path).args())
    assert result.returncode == 4, result.stderr
    assert result.stdout == ""
    assert f"input refused: {case.code}" in result.stderr


@pytest.mark.req("FR-09")
@pytest.mark.parametrize("case", REFUSED, ids=name)
def test_scan_refuses_the_policy_before_opening_the_medium(tmp_path: Path, case: Refused) -> None:
    # The image has no file system: a scan that looked at it first would refuse it for that reason.
    signed = case.make(tmp_path / "policy")
    report, output = tmp_path / "report.json", tmp_path / "output"
    engine = fake_engine_config(tmp_path, "fake-av")
    result = run_ostia(
        "scan",
        "--image",
        blank_image(),
        "--report",
        report,
        "--output",
        output,
        *signed.args(),
        "--dev-engine",
        engine,
    )
    assert result.returncode == 4, result.stderr
    refused = load_report(report)
    assert refused["refusal"]["code"] == case.code
    assert refused["policy"]["sha256"] == sha256(signed.policy.read_bytes())
    assert refused["objects"] == []
    assert refused["medium_verdict"]["blocked"] is True
    assert not output.exists() or not any(output.iterdir())


@pytest.mark.req("FR-09")
def test_scan_without_a_signature_is_refused_and_writes_nothing(tmp_path: Path) -> None:
    signed = valid(tmp_path / "policy")
    report, output = tmp_path / "report.json", tmp_path / "output"
    result = run_ostia(
        "scan",
        "--image",
        blank_image(),
        "--report",
        report,
        "--output",
        output,
        "--policy",
        signed.policy,
        "--trust",
        signed.trust,
    )
    assert result.returncode == 2, result.stderr
    assert "--policy-sig" in result.stderr
    assert not report.exists()
    assert not output.exists()
