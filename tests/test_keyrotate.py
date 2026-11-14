from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from base64 import b64encode, urlsafe_b64encode
from datetime import timezone
from pathlib import Path

from keyrotate.cli import main
from keyrotate.clock import format_timestamp, parse_timestamp
from keyrotate.registry import TIME_FIELDS, build_registry, decode_material
from keyrotate.verify import build_report


ROOT = Path(__file__).resolve().parents[1]
KEYS_PATH = ROOT / "demo" / "keys.json"
SIGNATURES_PATH = ROOT / "demo" / "signatures.json"


def load_fixtures() -> tuple[dict, dict]:
    with KEYS_PATH.open(encoding="utf-8") as file:
        keys_payload = json.load(file)
    with SIGNATURES_PATH.open(encoding="utf-8") as file:
        signatures_payload = json.load(file)
    return keys_payload, signatures_payload


EXPECTED_FINGERPRINTS = {
    ("kms-prod-signing", 1): ("a9f6625ef3af7f94", "a9f6625ef3af7f94"),
    ("kms-prod-signing", 2): ("4604a0f92e0cd3d3", "7c5022f42d85deca"),
    ("kms-prod-signing", 3): ("11aacb69f1bbee2c", "78b0f946dc0703a6"),
    ("kms-legacy-signing", 1): ("c9732a5c16fa74c6", "c9732a5c16fa74c6"),
    ("kms-partner-verify", 1): ("6bdcabcca301c270", "6bdcabcca301c270"),
    ("kms-partner-verify", 2): ("c9732a5c16fa74c6", "8c7a7e7ee1fc7623"),
    ("kms-batch-signing", 1): ("c49001ee173a7e04", "c49001ee173a7e04"),
    ("kms-legacy-verify", 1): ("c9732a5c16fa74c6", "c9732a5c16fa74c6"),
    ("kms-rotating-signing", 1): ("6ea658c31e58e6a2", "6ea658c31e58e6a2"),
    ("kms-rotating-signing", 2): ("cfaef3ed9bcb9707", "947f9d90ee563459"),
}

EXPECTED_REGISTRY_TIMES = {
    ("kms-prod-signing", 1): (
        "2026-01-05T00:00:00Z",
        "2026-02-28T00:00:00Z",
        None,
        None,
    ),
    ("kms-prod-signing", 2): (
        "2026-03-20T00:00:00Z",
        "2026-07-01T00:00:00Z",
        "2026-07-15T00:00:00Z",
        None,
    ),
    ("kms-prod-signing", 3): (
        "2026-07-20T00:00:00Z",
        "2026-10-01T00:00:00Z",
        "2026-10-15T00:00:00Z",
        "2026-08-20T00:00:00Z",
    ),
    ("kms-legacy-signing", 1): (
        "2026-01-01T00:00:00Z",
        "2026-08-31T00:00:00Z",
        None,
        None,
    ),
    ("kms-partner-verify", 1): (
        "2026-01-01T00:00:00Z",
        "2026-03-31T00:00:00Z",
        None,
        None,
    ),
    ("kms-partner-verify", 2): (
        "2026-03-01T00:00:00Z",
        "2026-06-30T00:00:00Z",
        None,
        "2026-05-01T00:00:00Z",
    ),
    ("kms-batch-signing", 1): (
        "2026-01-01T00:00:00Z",
        "2026-03-31T00:00:00Z",
        "2026-06-30T00:00:00Z",
        "2026-04-15T00:00:00Z",
    ),
    ("kms-legacy-verify", 1): (
        "2026-01-01T00:00:00Z",
        "2026-12-31T00:00:00Z",
        None,
        None,
    ),
    ("kms-rotating-signing", 1): (
        "2026-03-10T00:00:00Z",
        "2026-09-30T00:00:00Z",
        None,
        None,
    ),
    ("kms-rotating-signing", 2): (
        "2026-03-10T00:00:00Z",
        "2026-12-31T00:00:00Z",
        None,
        None,
    ),
}

EXPECTED_SIGNATURES = [
    ("s01", "active", True, "kms-prod-signing#1", "a9f6625ef3af7f94", "a9f6625ef3af7f94", "not_before", "2026-01-05T00:00:00Z", None),
    ("s02", "not_yet_valid", False, None, None, None, "not_before", "2026-01-05T00:00:00Z", None),
    ("s03", "active", True, "kms-prod-signing#1", "a9f6625ef3af7f94", "a9f6625ef3af7f94", "not_before", "2026-01-05T00:00:00Z", None),
    ("s04", "expired", False, "kms-prod-signing#1", "a9f6625ef3af7f94", "a9f6625ef3af7f94", "not_after", "2026-02-28T00:00:00Z", 432000),
    ("s05", "active", True, "kms-prod-signing#2", "4604a0f92e0cd3d3", "7c5022f42d85deca", "not_before", "2026-03-20T00:00:00Z", None),
    ("s06", "active", True, "kms-prod-signing#2", "4604a0f92e0cd3d3", "7c5022f42d85deca", "not_before", "2026-03-20T00:00:00Z", None),
    ("s07", "grace", True, "kms-prod-signing#2", "4604a0f92e0cd3d3", "7c5022f42d85deca", "grace_until", "2026-07-15T00:00:00Z", None),
    ("s08", "grace", True, "kms-prod-signing#2", "4604a0f92e0cd3d3", "7c5022f42d85deca", "grace_until", "2026-07-15T00:00:00Z", None),
    ("s09", "expired", False, "kms-prod-signing#2", "4604a0f92e0cd3d3", "7c5022f42d85deca", "not_after", "2026-07-01T00:00:00Z", 1209601),
    ("s10", "expired", False, "kms-prod-signing#2", "4604a0f92e0cd3d3", "7c5022f42d85deca", "not_after", "2026-07-01T00:00:00Z", 1468800),
    ("s11", "revoked", False, "kms-prod-signing#3", "11aacb69f1bbee2c", "78b0f946dc0703a6", "revoked_at", "2026-08-20T00:00:00Z", None),
    ("s12", "revoked", False, "kms-prod-signing#3", "11aacb69f1bbee2c", "78b0f946dc0703a6", "revoked_at", "2026-08-20T00:00:00Z", None),
    ("s13", "revoked", False, "kms-prod-signing#3", "11aacb69f1bbee2c", "78b0f946dc0703a6", "revoked_at", "2026-08-20T00:00:00Z", None),
    ("s14", "not_yet_valid", False, None, None, None, "not_before", "2026-01-01T00:00:00Z", None),
    ("s15", "active", True, "kms-legacy-signing#1", "c9732a5c16fa74c6", "c9732a5c16fa74c6", "not_before", "2026-01-01T00:00:00Z", None),
    ("s16", "expired", False, "kms-legacy-signing#1", "c9732a5c16fa74c6", "c9732a5c16fa74c6", "not_after", "2026-08-31T00:00:00Z", 1296000),
    ("s17", "active", True, "kms-partner-verify#1", "6bdcabcca301c270", "6bdcabcca301c270", "not_before", "2026-01-01T00:00:00Z", None),
    ("s18", "active", True, "kms-partner-verify#2", "c9732a5c16fa74c6", "8c7a7e7ee1fc7623", "not_before", "2026-03-01T00:00:00Z", None),
    ("s19", "revoked", False, "kms-partner-verify#2", "c9732a5c16fa74c6", "8c7a7e7ee1fc7623", "revoked_at", "2026-05-01T00:00:00Z", None),
    ("s20", "revoked", False, "kms-partner-verify#2", "c9732a5c16fa74c6", "8c7a7e7ee1fc7623", "revoked_at", "2026-05-01T00:00:00Z", None),
    ("s21", "active", True, "kms-batch-signing#1", "c49001ee173a7e04", "c49001ee173a7e04", "not_before", "2026-01-01T00:00:00Z", None),
    ("s22", "grace", True, "kms-batch-signing#1", "c49001ee173a7e04", "c49001ee173a7e04", "grace_until", "2026-06-30T00:00:00Z", None),
    ("s23", "revoked", False, "kms-batch-signing#1", "c49001ee173a7e04", "c49001ee173a7e04", "revoked_at", "2026-04-15T00:00:00Z", None),
    ("s24", "revoked", False, "kms-batch-signing#1", "c49001ee173a7e04", "c49001ee173a7e04", "revoked_at", "2026-04-15T00:00:00Z", None),
    ("s25", "unknown_key", False, None, None, None, "key_id_absent", None, None),
    ("s26", "not_yet_valid", False, None, None, None, "not_before", "2026-01-05T00:00:00Z", None),
    ("s27", "grace", True, "kms-prod-signing#2", "4604a0f92e0cd3d3", "7c5022f42d85deca", "grace_until", "2026-07-15T00:00:00Z", None),
    ("s28", "active", True, "kms-rotating-signing#2", "cfaef3ed9bcb9707", "947f9d90ee563459", "not_before", "2026-03-10T00:00:00Z", None),
    ("s29", "active", True, "kms-legacy-verify#1", "c9732a5c16fa74c6", "c9732a5c16fa74c6", "not_before", "2026-01-01T00:00:00Z", None),
]


class KeyRotateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.keys_payload, cls.signatures_payload = load_fixtures()
        cls.report = build_report(cls.keys_payload, cls.signatures_payload)

    def test_01_fixture_sizes(self) -> None:
        self.assertEqual(len(self.keys_payload["keys"]), 10)
        self.assertEqual(len(self.signatures_payload["signatures"]), 29)
        self.assertEqual(len(self.report["registry"]), 10)
        self.assertEqual(len(self.report["signatures"]), 29)

    def test_02_all_timestamp_forms_utc_seconds(self) -> None:
        self.assertEqual(
            format_timestamp(parse_timestamp("2026-01-05T00:00:00Z")),
            "2026-01-05T00:00:00Z",
        )
        self.assertEqual(
            format_timestamp(parse_timestamp("2026-01-05T08:00:00+08:00")),
            "2026-01-05T00:00:00Z",
        )
        self.assertEqual(
            format_timestamp(parse_timestamp("2026-02-27T21:00:00-04:00")),
            "2026-02-28T01:00:00Z",
        )
        self.assertEqual(
            format_timestamp(parse_timestamp("20260320T000000Z")),
            "2026-03-20T00:00:00Z",
        )
        self.assertEqual(format_timestamp(parse_timestamp(1772323200)), "2026-03-01T00:00:00Z")
        self.assertEqual(
            format_timestamp(parse_timestamp("2026-01-04T23:59:59.500Z")),
            "2026-01-04T23:59:59Z",
        )
        self.assertEqual(parse_timestamp(1772323200).tzinfo, timezone.utc)

    def test_03_base64_whitespace_and_alphabets(self) -> None:
        standard = self.keys_payload["keys"][3]["material_b64"]
        url_safe = self.keys_payload["keys"][5]["material_b64"]
        embedded_newline = self.keys_payload["keys"][7]["material_b64"]
        self.assertEqual(
            decode_material("base64", standard),
            decode_material("base64url", url_safe),
        )
        self.assertEqual(
            decode_material("base64", embedded_newline),
            decode_material("base64", standard),
        )
        self.assertEqual(
            decode_material("base64", "QUJD RCBF\nRkc=\t"),
            b"ABCD EFG",
        )
        self.assertEqual(decode_material("base64url", "QUJDRA"), b"ABCD")

    def test_04_fingerprints_and_lineages(self) -> None:
        for entry in self.report["registry"]:
            identity = (entry["key_id"], entry["generation"])
            fingerprint, lineage = EXPECTED_FINGERPRINTS[identity]
            self.assertEqual(entry["fingerprint"], fingerprint)
            self.assertEqual(entry["lineage"], lineage)
        legacy = next(
            item
            for item in self.report["registry"]
            if item["key_id"] == "kms-legacy-signing"
        )
        partner = next(
            item
            for item in self.report["registry"]
            if (item["key_id"], item["generation"]) == ("kms-partner-verify", 2)
        )
        self.assertEqual(legacy["fingerprint"], partner["fingerprint"])
        self.assertNotEqual(legacy["lineage"], partner["lineage"])

    def test_05_registry_normalized_times(self) -> None:
        for entry in self.report["registry"]:
            identity = (entry["key_id"], entry["generation"])
            self.assertEqual(
                tuple(entry[field] for field in TIME_FIELDS),
                EXPECTED_REGISTRY_TIMES[identity],
            )

    def test_06_each_signature_matches_expected_result(self) -> None:
        expected_fields = (
            "sig_id",
            "state",
            "verified",
            "effective_key",
            "effective_fingerprint",
            "effective_lineage",
            "decisive_field",
            "decisive_at",
            "overdue_seconds",
        )
        for entry, expected in zip(self.report["signatures"], EXPECTED_SIGNATURES):
            with self.subTest(sig_id=entry["sig_id"]):
                self.assertEqual(tuple(entry[field] for field in expected_fields), expected)

    def test_07_boundary_revocation_and_selection_rules(self) -> None:
        by_sig = {entry["sig_id"]: entry for entry in self.report["signatures"]}
        self.assertEqual(by_sig["s01"]["state"], "active")
        self.assertEqual(by_sig["s02"]["state"], "not_yet_valid")
        self.assertEqual(by_sig["s26"]["state"], "not_yet_valid")
        self.assertEqual(by_sig["s27"]["state"], "grace")
        for sig_id in ("s11", "s12", "s13", "s19", "s20"):
            self.assertEqual(by_sig[sig_id]["state"], "revoked")
            self.assertEqual(by_sig[sig_id]["decisive_field"], "revoked_at")
        self.assertEqual(by_sig["s19"]["decisive_at"], "2026-05-01T00:00:00Z")
        self.assertEqual(by_sig["s18"]["effective_key"], "kms-partner-verify#2")
        self.assertEqual(by_sig["s22"]["state"], "grace")
        self.assertEqual(by_sig["s23"]["state"], "revoked")
        self.assertEqual(by_sig["s24"]["state"], "revoked")
        self.assertEqual(by_sig["s28"]["effective_key"], "kms-rotating-signing#2")
        self.assertEqual(by_sig["s29"]["effective_fingerprint"], "c9732a5c16fa74c6")

    def _comparable_report(self, report: dict) -> dict:
        return {
            "signatures": [
                {
                    "state": item["state"],
                    "verified": item["verified"],
                    "effective_key": item["effective_key"],
                    "effective_fingerprint": item["effective_fingerprint"],
                    "effective_lineage": item["effective_lineage"],
                    "decisive_field": item["decisive_field"],
                    "decisive_at": item["decisive_at"],
                    "overdue_seconds": item["overdue_seconds"],
                }
                for item in report["signatures"]
            ],
            "registry": [
                {
                    "key_id": item["key_id"],
                    "generation": item["generation"],
                    "fingerprint": item["fingerprint"],
                    "lineage": item["lineage"],
                    "not_before": item["not_before"],
                    "not_after": item["not_after"],
                    "grace_until": item["grace_until"],
                    "revoked_at": item["revoked_at"],
                }
                for item in report["registry"]
            ],
            "summary": report["summary"],
        }

    def _unix_and_reencoded_payloads(self) -> tuple[dict, dict]:
        keys_payload = copy.deepcopy(self.keys_payload)
        for record in keys_payload["keys"]:
            material = decode_material(record["encoding"], record["material_b64"])
            if record["encoding"] == "base64":
                record["encoding"] = "base64url"
                record["material_b64"] = urlsafe_b64encode(material).decode().rstrip("=")
            else:
                record["encoding"] = "base64"
                record["material_b64"] = b64encode(material).decode()
            for field in TIME_FIELDS:
                if record[field] is not None:
                    record[field] = int(parse_timestamp(record[field]).timestamp())

        signatures_payload = copy.deepcopy(self.signatures_payload)
        for record in signatures_payload["signatures"]:
            record["signed_at"] = int(parse_timestamp(record["signed_at"]).timestamp())
        return keys_payload, signatures_payload

    def test_08_alternate_unix_and_base64_representation_is_equivalent(self) -> None:
        alternate_keys, alternate_signatures = self._unix_and_reencoded_payloads()
        alternate_report = build_report(alternate_keys, alternate_signatures)
        self.assertEqual(
            self._comparable_report(alternate_report),
            self._comparable_report(self.report),
        )
        self.assertNotIn("\\n", alternate_keys["keys"][7]["material_b64"])

    def test_09_modified_grace_and_revocation_variant(self) -> None:
        keys_payload, signatures_payload = load_fixtures()
        for record in keys_payload["keys"]:
            if record["key_id"] == "kms-prod-signing" and record["generation"] == 2:
                record["grace_until"] = "2026-07-20T00:00:00Z"
            if record["key_id"] == "kms-batch-signing":
                record["revoked_at"] = "2026-03-01T00:00:00Z"

        changed_report = build_report(keys_payload, signatures_payload)
        changed = {entry["sig_id"]: entry for entry in changed_report["signatures"]}
        for sig_id in ("s07", "s08", "s27", "s09", "s10"):
            self.assertEqual(changed[sig_id]["state"], "grace")
            self.assertEqual(changed[sig_id]["decisive_field"], "grace_until")
            self.assertEqual(changed[sig_id]["decisive_at"], "2026-07-20T00:00:00Z")
            self.assertIsNone(changed[sig_id]["overdue_seconds"])
        for sig_id in ("s22", "s23", "s24"):
            self.assertEqual(changed[sig_id]["state"], "revoked")
            self.assertEqual(changed[sig_id]["decisive_at"], "2026-03-01T00:00:00Z")

        original = {entry["sig_id"]: entry for entry in self.report["signatures"]}
        changed_ids = {"s07", "s08", "s27", "s09", "s10", "s22", "s23", "s24"}
        for sig_id in original:
            if sig_id not in changed_ids:
                self.assertEqual(changed[sig_id]["state"], original[sig_id]["state"])
                self.assertEqual(changed[sig_id]["verified"], original[sig_id]["verified"])
        self.assertEqual(changed_report["summary"]["verified"], 15)
        self.assertEqual(
            changed_report["summary"]["by_state"],
            {
                "active": 10,
                "grace": 5,
                "expired": 2,
                "revoked": 8,
                "not_yet_valid": 3,
                "unknown_key": 1,
            },
        )

    def test_10_schema_summary_determinism_and_cli(self) -> None:
        self.assertEqual(
            self.report["summary"],
            {
                "signatures": 29,
                "verified": 14,
                "by_state": {
                    "active": 10,
                    "grace": 4,
                    "expired": 4,
                    "revoked": 7,
                    "not_yet_valid": 3,
                    "unknown_key": 1,
                },
                "generations": 10,
            },
        )
        signature_fields = [
            "sig_id",
            "key_id",
            "signed_at",
            "state",
            "verified",
            "effective_key",
            "effective_fingerprint",
            "effective_lineage",
            "decisive_field",
            "decisive_at",
            "overdue_seconds",
        ]
        registry_fields = [
            "key_id",
            "generation",
            "fingerprint",
            "lineage",
            "not_before",
            "not_after",
            "grace_until",
            "revoked_at",
        ]
        self.assertEqual(list(self.report.keys()), ["signatures", "registry", "summary"])
        self.assertEqual(list(self.report["summary"].keys()), ["signatures", "verified", "by_state", "generations"])
        self.assertEqual(list(self.report["summary"]["by_state"].keys()), ["active", "grace", "expired", "revoked", "not_yet_valid", "unknown_key"])
        for entry in self.report["signatures"]:
            self.assertEqual(list(entry.keys()), signature_fields)
            if entry["state"] != "expired":
                self.assertIsNone(entry["overdue_seconds"])
            else:
                self.assertIsInstance(entry["overdue_seconds"], int)
        for entry in self.report["registry"]:
            self.assertEqual(list(entry.keys()), registry_fields)

        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            main(["--keys", str(KEYS_PATH), "--signatures", str(SIGNATURES_PATH), "--out", str(first)])
            main(["--keys", str(KEYS_PATH), "--signatures", str(SIGNATURES_PATH), "--out", str(second)])
            self.assertEqual(first.read_bytes(), second.read_bytes())
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "keyrotate.cli",
                    "--keys",
                    str(KEYS_PATH),
                    "--signatures",
                    str(SIGNATURES_PATH),
                    "--out",
                    str(Path(directory) / "subprocess.json"),
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(len(completed.stdout.splitlines()), 1)
            self.assertIn("signatures=29", completed.stdout)
            self.assertIn("verified=14", completed.stdout)
