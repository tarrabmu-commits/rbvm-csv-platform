#!/usr/bin/env python3
"""Dependency-free checks for the CISA KEV official-source adapter."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/fetch-cisa-kev-snapshot.py"


def load_module():
    spec = importlib.util.spec_from_file_location("cisa_kev_source", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def payload(count=2, vulnerabilities=None):
    if vulnerabilities is None:
        vulnerabilities = [
            {
                "cveID": "CVE-2026-10001",
                "dateAdded": "2026-08-18",
                "dueDate": "2026-09-01",
                "knownRansomwareCampaignUse": "Known",
            },
            {
                "cveID": "CVE-2026-10002",
                "dateAdded": "2026-08-19",
                "dueDate": "2026-09-02",
                "knownRansomwareCampaignUse": "Unknown",
            },
        ]
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.08.19",
        "dateReleased": "2026-08-19T09:00:00.000Z",
        "count": count,
        "vulnerabilities": vulnerabilities,
    }


def encode(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=False).encode("utf-8")


def assert_rejected(operation, expected_fragment):
    try:
        operation()
    except RuntimeError as error:
        assert expected_fragment in str(error), (expected_fragment, str(error))
        return
    raise AssertionError(f"expected rejection containing {expected_fragment!r}")


def main():
    module = load_module()
    observed = "2026-08-19T10:00:00Z"
    raw = encode(payload())
    snapshot = module.parse_and_validate(raw, observed)

    assert snapshot["artifactType"] == "CISA_KEV_VALIDATED_SNAPSHOT"
    assert snapshot["source"] == module.CISA_KEV_JSON
    assert snapshot["catalogVersion"] == "2026.08.19"
    assert snapshot["declaredCount"] == 2
    assert snapshot["parsedCount"] == 2
    assert snapshot["complete"] is True
    assert snapshot["sha256"] == hashlib.sha256(raw).hexdigest()
    assert snapshot["vulnerabilities"][0]["knownRansomwareCampaignUse"] == "KNOWN"
    assert snapshot["vulnerabilities"][1]["knownRansomwareCampaignUse"] == "UNKNOWN"

    assert_rejected(
        lambda: module.parse_and_validate(encode(payload(count=3)), observed),
        "snapshot is incomplete",
    )

    duplicate = payload(vulnerabilities=[
        {
            "cveID": "CVE-2026-10001",
            "dateAdded": "2026-08-18",
            "dueDate": "2026-09-01",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2026-10001",
            "dateAdded": "2026-08-18",
            "dueDate": "2026-09-01",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ])
    assert_rejected(
        lambda: module.parse_and_validate(encode(duplicate), observed),
        "duplicate CISA KEV CVE_ID",
    )

    malformed_use = payload(vulnerabilities=[
        {
            "cveID": "CVE-2026-10001",
            "dateAdded": "2026-08-18",
            "dueDate": "2026-09-01",
            "knownRansomwareCampaignUse": "No",
        },
    ], count=1)
    assert_rejected(
        lambda: module.parse_and_validate(encode(malformed_use), observed),
        "must be Known or Unknown",
    )

    missing_metadata = payload(vulnerabilities=[
        {
            "cveID": "CVE-2026-10001",
            "dateAdded": "2026-08-18",
            "knownRansomwareCampaignUse": "Known",
        },
    ], count=1)
    assert_rejected(
        lambda: module.parse_and_validate(encode(missing_metadata), observed),
        "dueDate must be a non-blank string",
    )

    assert module.CISA_KEV_JSON.startswith("https://www.cisa.gov/")
    source = SCRIPT.read_text(encoding="utf-8")
    forbidden = ["priorityTier", "riskScore", "epss", "SLA", "psql", "jdbc:"]
    for token in forbidden:
        assert token not in source, token

    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        input_path = directory / "kev.json"
        output_path = directory / "snapshot.json"
        input_path.write_bytes(raw)
        bytes_read = module.read_offline_bytes(input_path)
        assert bytes_read == raw
        module.write_json(output_path, snapshot)
        restored = json.loads(output_path.read_text(encoding="utf-8"))
        assert restored["sha256"] == snapshot["sha256"]

    print("CISA KEV source adapter checks: PASS")


if __name__ == "__main__":
    main()
