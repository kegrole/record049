from __future__ import annotations

import re
from base64 import b64decode, urlsafe_b64decode
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .clock import parse_timestamp
from .lineage import build_lineages, fingerprint


TIME_FIELDS = ("not_before", "not_after", "grace_until", "revoked_at")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")


@dataclass(frozen=True)
class RegisteredKey:
    key_id: str
    generation: int
    encoding: str
    material: bytes
    fingerprint: str
    lineage: str
    not_before: datetime
    not_after: datetime | None
    grace_until: datetime | None
    revoked_at: datetime | None


def decode_material(encoding: str, material_b64: str) -> bytes:
    compact_material = "".join(material_b64.split())
    padded_material = compact_material + "=" * ((-len(compact_material)) % 4)

    if encoding == "base64":
        if not _BASE64_RE.fullmatch(padded_material):
            raise ValueError("material is not valid standard base64")
        return b64decode(padded_material, validate=True)

    if encoding == "base64url":
        if not _BASE64URL_RE.fullmatch(padded_material):
            raise ValueError("material is not valid base64url")
        return urlsafe_b64decode(padded_material)

    raise ValueError(f"unsupported encoding: {encoding}")


def _parse_optional_time(value: Any) -> datetime | None:
    if value is None:
        return None
    return parse_timestamp(value)


def build_registry(records: list[dict[str, Any]]) -> list[RegisteredKey]:
    preliminary: list[RegisteredKey] = []

    for record in records:
        material = decode_material(record["encoding"], record["material_b64"])
        preliminary.append(
            RegisteredKey(
                key_id=record["key_id"],
                generation=record["generation"],
                encoding=record["encoding"],
                material=material,
                fingerprint=fingerprint(material),
                lineage="",
                not_before=parse_timestamp(record["not_before"]),
                not_after=_parse_optional_time(record["not_after"]),
                grace_until=_parse_optional_time(record["grace_until"]),
                revoked_at=_parse_optional_time(record["revoked_at"]),
            )
        )

    grouped: dict[str, list[RegisteredKey]] = {}
    for key in preliminary:
        grouped.setdefault(key.key_id, []).append(key)

    lineage_by_generation: dict[tuple[str, int], str] = {}
    for key_id, group in grouped.items():
        group_lineages = build_lineages(
            (key.generation, key.material, key.fingerprint) for key in group
        )
        for generation, lineage in group_lineages.items():
            lineage_by_generation[(key_id, generation)] = lineage

    return [
        RegisteredKey(
            key_id=key.key_id,
            generation=key.generation,
            encoding=key.encoding,
            material=key.material,
            fingerprint=key.fingerprint,
            lineage=lineage_by_generation[(key.key_id, key.generation)],
            not_before=key.not_before,
            not_after=key.not_after,
            grace_until=key.grace_until,
            revoked_at=key.revoked_at,
        )
        for key in preliminary
    ]
