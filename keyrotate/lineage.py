from __future__ import annotations

import hashlib
from collections.abc import Iterable


def fingerprint(material: bytes) -> str:
    return hashlib.sha256(material).hexdigest()[:16]


def next_lineage(previous_lineage: str, material: bytes) -> str:
    linked_material = bytes.fromhex(previous_lineage) + material
    return hashlib.sha256(linked_material).hexdigest()[:16]


def build_lineages(generations: Iterable[tuple[int, bytes, str]]) -> dict[int, str]:
    lineages: dict[int, str] = {}
    previous_lineage: str | None = None

    for generation, material, current_fingerprint in sorted(
        generations, key=lambda item: item[0]
    ):
        if previous_lineage is None:
            lineage = current_fingerprint
        else:
            lineage = next_lineage(previous_lineage, material)

        lineages[generation] = lineage
        previous_lineage = lineage

    return lineages
