from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .registry import RegisteredKey


STATE_NAMES = ("active", "grace", "expired", "revoked", "not_yet_valid", "unknown_key")


@dataclass(frozen=True)
class Verification:
    state: str
    verified: bool
    effective_key: str | None
    effective_fingerprint: str | None
    effective_lineage: str | None
    decisive_field: str
    decisive_at: datetime | None
    overdue_seconds: int | None


def select_effective_key(
    keys: list[RegisteredKey], signed_at: datetime
) -> RegisteredKey | None:
    available = [key for key in keys if key.not_before <= signed_at]
    if not available:
        return None
    return max(available, key=lambda key: (key.not_before, key.generation))


def evaluate_signature(
    registry: list[RegisteredKey], key_id: str, signed_at: datetime
) -> Verification:
    key_generations = [key for key in registry if key.key_id == key_id]

    if not key_generations:
        return Verification(
            state="unknown_key",
            verified=False,
            effective_key=None,
            effective_fingerprint=None,
            effective_lineage=None,
            decisive_field="key_id_absent",
            decisive_at=None,
            overdue_seconds=None,
        )

    effective = select_effective_key(key_generations, signed_at)
    if effective is None:
        earliest = min(key_generations, key=lambda key: key.not_before)
        return Verification(
            state="not_yet_valid",
            verified=False,
            effective_key=None,
            effective_fingerprint=None,
            effective_lineage=None,
            decisive_field="not_before",
            decisive_at=earliest.not_before,
            overdue_seconds=None,
        )

    effective_name = f"{effective.key_id}#{effective.generation}"

    if effective.revoked_at is not None and effective.revoked_at <= signed_at:
        return Verification(
            state="revoked",
            verified=False,
            effective_key=effective_name,
            effective_fingerprint=effective.fingerprint,
            effective_lineage=effective.lineage,
            decisive_field="revoked_at",
            decisive_at=effective.revoked_at,
            overdue_seconds=None,
        )

    if effective.not_after is not None and effective.not_after < signed_at:
        if effective.grace_until is not None and signed_at <= effective.grace_until:
            return Verification(
                state="grace",
                verified=True,
                effective_key=effective_name,
                effective_fingerprint=effective.fingerprint,
                effective_lineage=effective.lineage,
                decisive_field="grace_until",
                decisive_at=effective.grace_until,
                overdue_seconds=None,
            )

        return Verification(
            state="expired",
            verified=False,
            effective_key=effective_name,
            effective_fingerprint=effective.fingerprint,
            effective_lineage=effective.lineage,
            decisive_field="not_after",
            decisive_at=effective.not_after,
            overdue_seconds=int((signed_at - effective.not_after).total_seconds()),
        )

    return Verification(
        state="active",
        verified=True,
        effective_key=effective_name,
        effective_fingerprint=effective.fingerprint,
        effective_lineage=effective.lineage,
        decisive_field="not_before",
        decisive_at=effective.not_before,
        overdue_seconds=None,
    )
