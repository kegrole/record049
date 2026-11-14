from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .clock import format_timestamp, parse_timestamp
from .registry import RegisteredKey, build_registry
from .states import STATE_NAMES, Verification, evaluate_signature


def load_json(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as file:
        return json.load(file)


def _registry_entry(key: RegisteredKey) -> dict[str, Any]:
    return {
        "key_id": key.key_id,
        "generation": key.generation,
        "fingerprint": key.fingerprint,
        "lineage": key.lineage,
        "not_before": format_timestamp(key.not_before),
        "not_after": format_timestamp(key.not_after) if key.not_after else None,
        "grace_until": format_timestamp(key.grace_until) if key.grace_until else None,
        "revoked_at": format_timestamp(key.revoked_at) if key.revoked_at else None,
    }


def _signature_entry(
    record: dict[str, Any], verification: Verification, signed_at: datetime
) -> dict[str, Any]:
    return {
        "sig_id": record["sig_id"],
        "key_id": record["key_id"],
        "signed_at": format_timestamp(signed_at),
        "state": verification.state,
        "verified": verification.verified,
        "effective_key": verification.effective_key,
        "effective_fingerprint": verification.effective_fingerprint,
        "effective_lineage": verification.effective_lineage,
        "decisive_field": verification.decisive_field,
        "decisive_at": (
            format_timestamp(verification.decisive_at)
            if verification.decisive_at is not None
            else None
        ),
        "overdue_seconds": verification.overdue_seconds,
    }


def build_report(
    keys_payload: dict[str, Any], signatures_payload: dict[str, Any]
) -> dict[str, Any]:
    registry = build_registry(keys_payload["keys"])
    signature_results: list[dict[str, Any]] = []
    by_state = {state: 0 for state in STATE_NAMES}

    for record in signatures_payload["signatures"]:
        signed_at = parse_timestamp(record["signed_at"])
        verification = evaluate_signature(
            registry=registry,
            key_id=record["key_id"],
            signed_at=signed_at,
        )
        by_state[verification.state] += 1
        signature_results.append(_signature_entry(record, verification, signed_at))

    return {
        "signatures": signature_results,
        "registry": [_registry_entry(key) for key in registry],
        "summary": {
            "signatures": len(signature_results),
            "verified": sum(item["verified"] for item in signature_results),
            "by_state": by_state,
            "generations": len(registry),
        },
    }


def verify_files(keys_path: str | Path, signatures_path: str | Path) -> dict[str, Any]:
    return build_report(load_json(keys_path), load_json(signatures_path))
