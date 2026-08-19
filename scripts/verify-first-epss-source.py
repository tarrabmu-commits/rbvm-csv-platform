#!/usr/bin/env python3
"""Dependency-free checks for the official FIRST EPSS bulk source adapter."""

import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/fetch-first-epss-snapshot.py"


def load_module():
    spec = importlib.util.spec_from_file_location("first_epss_source", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def feed(rows=None, metadata="#model_version:v2026.06.15,score_date:2026-08-18T13:30:00Z"):
    if rows is None:
        rows = [
            "CVE-2026-10001,0.250000000,0.810000000",
            "CVE-2026-10002,0.010000000,0.310000000",
            "CVE-2026-10003,0.900000000,0.990000000",
        ]
    text = metadata + "\n" + "cve,epss,percentile\n" + "\n".join(rows) + "\n"
    return gzip.compress(text.encode("utf-8"), mtime=0)


def assert_rejected(operation, expected_fragment):
    try:
        operation()
    except RuntimeError as error:
        assert expected_fragment in str(error), (expected_fragment, str(error))
        return
    raise AssertionError(f"expected rejection containing {expected_fragment!r}")


def parser_validates_complete_feed_and_selects_requested_cves():
    module = load_module()
    payload = feed()
    parsed = module.parse_feed(payload, ["CVE-2026-10001", "CVE-2026-19999"])
    assert parsed["modelVersion"] == "v2026.06.15"
    assert parsed["scoreDate"] == "2026-08-18"
    assert parsed["feedRowCount"] == 3
    assert parsed["scores"] == [{
        "cveId": "CVE-2026-10001",
        "epss": "0.250000000",
        "percentile": "0.810000000",
    }]
    assert parsed["missingCves"] == ["CVE-2026-19999"]

    duplicate = feed(rows=[
        "CVE-2026-10001,0.2,0.8",
        "CVE-2026-10001,0.2,0.8",
    ])
    assert_rejected(
        lambda: module.parse_feed(duplicate, ["CVE-2026-10001"]),
        "duplicate CVE ID",
    )

    invalid_score = feed(rows=["CVE-2026-10001,1.01,0.8"])
    assert_rejected(
        lambda: module.parse_feed(invalid_score, ["CVE-2026-10001"]),
        "epss must be between 0 and 1",
    )

    invalid_percentile = feed(rows=["CVE-2026-10001,0.2,-0.01"])
    assert_rejected(
        lambda: module.parse_feed(invalid_percentile, ["CVE-2026-10001"]),
        "percentile must be between 0 and 1",
    )

    missing_metadata = feed(metadata="#publication:2026-08-18")
    assert_rejected(
        lambda: module.parse_feed(missing_metadata, ["CVE-2026-10001"]),
        "model_version and score_date",
    )


def offline_cli_preserves_provenance_and_missing_is_not_zero():
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        input_csv = directory / "wazuh.csv"
        source = directory / "epss.csv.gz"
        output = directory / "snapshot.json"
        input_csv.write_text(
            "Agent,CVE_ID,Severity,CVE_Description,Affected_Product,References,OS_name,Detected_At\n"
            "host-a,CVE-2026-10001,High,a,pkg-a,https://example.test/a,Ubuntu,2026-08-18T10:00:00Z\n"
            "host-b,CVE-2026-19999,Medium,b,pkg-b,https://example.test/b,Ubuntu,2026-08-18T10:01:00Z\n",
            encoding="utf-8",
        )
        payload = feed()
        source.write_bytes(payload)
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(input_csv),
                str(output),
                "--offline-input",
                str(source),
                "--observed-at",
                "2026-08-19T11:00:00Z",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "first_epss_snapshot=VALID" in result.stdout
        artifact = json.loads(output.read_text(encoding="utf-8"))
        assert artifact["artifactType"] == "FIRST_EPSS_VALIDATED_SNAPSHOT"
        assert artifact["source"] == "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
        assert artifact["acquisitionMode"] == "OFFLINE_REPLAY"
        assert artifact["observedAt"] == "2026-08-19T11:00:00Z"
        assert artifact["sourceBytesSha256"] == hashlib.sha256(payload).hexdigest()
        assert artifact["requestedCveCount"] == 2
        assert artifact["scoredCveCount"] == 1
        assert artifact["missingCveCount"] == 1
        assert artifact["missingCves"] == ["CVE-2026-19999"]
        assert artifact["scores"][0]["epss"] == "0.250000000"
        # Absence from the published feed remains missing evidence. It is never converted into 0.
        assert not any(score["cveId"] == "CVE-2026-19999" for score in artifact["scores"])


def source_boundary_contains_no_rbvm_decision_logic():
    module = load_module()
    assert module.EPSS_CURRENT_CSV_GZ == "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    source = SCRIPT.read_text(encoding="utf-8")
    forbidden = [
        "priorityTier",
        "riskScore",
        "knownExploited",
        "remediationSla",
        "psql",
        "jdbc:",
        "CVSS + EPSS",
        "CVSS * EPSS",
    ]
    for token in forbidden:
        assert token not in source, token


def main():
    parser_validates_complete_feed_and_selects_requested_cves()
    offline_cli_preserves_provenance_and_missing_is_not_zero()
    source_boundary_contains_no_rbvm_decision_logic()
    print("FIRST EPSS source adapter checks: PASS")


if __name__ == "__main__":
    main()
