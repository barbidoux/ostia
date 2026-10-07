"""Signed verdict policies (docs/contracts/policy.md): throwaway Ed25519 keys generated at test time."""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

DEFAULT_LIMITS = {
    "max_depth": 8,
    "max_ratio": 200,
    "max_total_bytes": 256 * 1024 * 1024,
    "max_entries": 10_000,
    "max_path_length": 1024,
    "engine_timeout_seconds": 30,
}


@dataclass(frozen=True)
class SignedPolicy:
    """The three files `ostia` needs, and the exact policy bytes."""

    policy: Path
    signature: Path
    trust: Path
    data: bytes

    def args(self) -> list[str]:
        return [
            "--policy",
            str(self.policy),
            "--policy-sig",
            str(self.signature),
            "--trust",
            str(self.trust),
        ]


def new_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def policy_document(
    engines: Mapping[str, Mapping[str, object]],
    *,
    version: str = "p1-acceptance",
    risky_types: tuple[str, ...] = ("pe",),
    k: int = 2,
    critical_severity: int = 4,
    r6: dict[str, bool] | None = None,
    limits: dict[str, int] | None = None,
) -> dict[str, Any]:
    """An `ostia.policy.v1` document; every R6 flag is on unless `r6` says otherwise."""
    flags = {
        "double_extension": True,
        "extension_mismatch": True,
        "single_detection": True,
        "suspicious_hint": True,
    }
    return {
        "schema": "ostia.policy.v1",
        "version": version,
        "engines": {engine_id: dict(entry) for engine_id, entry in engines.items()},
        "rules": {
            "R1": {"risky_types": list(risky_types)},
            "R2": {"k": k, "critical_severity": critical_severity},
            "R6": {**flags, **(r6 or {})},
        },
        "limits": {**DEFAULT_LIMITS, **(limits or {})},
    }


def write_signed_policy(
    directory: Path,
    policy: dict[str, Any] | bytes,
    *,
    key: Ed25519PrivateKey | None = None,
    trusted: Ed25519PrivateKey | None = None,
) -> SignedPolicy:
    """Write the policy, its detached signature by `key` (64 raw bytes) and the public key of `trusted`
    (32 raw bytes; `trusted` defaults to `key`)."""
    signer = key or new_key()
    data = policy if isinstance(policy, bytes) else json.dumps(policy, indent=2).encode()
    directory.mkdir(parents=True, exist_ok=True)
    paths = SignedPolicy(
        policy=directory / "policy.json",
        signature=directory / "policy.sig",
        trust=directory / "trusted.pub",
        data=data,
    )
    paths.policy.write_bytes(data)
    paths.signature.write_bytes(signer.sign(data))
    paths.trust.write_bytes(
        (trusted or signer).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    return paths
