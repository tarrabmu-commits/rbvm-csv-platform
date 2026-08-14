#!/usr/bin/env python3
"""Generate the deterministic 10,001-row WAZUH_CSV_V1 validation fixture."""

from __future__ import annotations

import csv
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


ASSET_COUNT = 5
VULNERABILITY_COUNT = 2_265
COMPONENT_COUNTS = (121, 121, 120, 120, 120)
CASE_COUNT = 7_521
EXPOSURE_COUNT = 9_090
OBSERVATION_COUNT = 10_001
SEVERITY_CHANGE_COUNT = 226


def cve(index: int) -> str:
    return f"CVE-2026-{10_000 + index}"


def build_cases() -> list[tuple[int, int]]:
    pairs: list[tuple[int, int]] = []
    used: set[tuple[int, int]] = set()

    # Guarantee that every CVE and every asset occurs before filling the matrix.
    for vulnerability in range(VULNERABILITY_COUNT):
        pair = (vulnerability % ASSET_COUNT, vulnerability)
        pairs.append(pair)
        used.add(pair)

    for asset in range(ASSET_COUNT):
        for vulnerability in range(VULNERABILITY_COUNT):
            pair = (asset, vulnerability)
            if pair not in used:
                pairs.append(pair)
                used.add(pair)
                if len(pairs) == CASE_COUNT:
                    return pairs
    raise AssertionError("case matrix is too small")


def main() -> None:
    destination = Path(sys.argv[1] if len(sys.argv) > 1 else "runtime-data/reference-10001.csv")
    destination.parent.mkdir(parents=True, exist_ok=True)
    cases = build_cases()

    exposures: list[tuple[int, int, int]] = []
    per_asset_seen = [0] * ASSET_COUNT
    for asset, vulnerability in cases:
        component = per_asset_seen[asset] % COMPONENT_COUNTS[asset]
        per_asset_seen[asset] += 1
        exposures.append((asset, vulnerability, component))

    extra = EXPOSURE_COUNT - CASE_COUNT
    for asset, vulnerability, component in exposures[:extra]:
        exposures.append((asset, vulnerability, (component + 1) % COMPONENT_COUNTS[asset]))

    base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    observations: list[tuple[int, int, int, str, datetime]] = []
    for index, (asset, vulnerability, component) in enumerate(exposures):
        severity = ("Critical", "High", "Medium", "Low")[index % 4]
        observations.append((asset, vulnerability, component, severity, base_time + timedelta(seconds=index)))

    duplicates = OBSERVATION_COUNT - EXPOSURE_COUNT
    for index in range(duplicates):
        asset, vulnerability, component = exposures[index]
        original_severity = observations[index][3]
        severity = "Critical" if index < SEVERITY_CHANGE_COUNT and original_severity != "Critical" else original_severity
        if index < SEVERITY_CHANGE_COUNT and severity == original_severity:
            severity = "High"
        observations.append((
            asset,
            vulnerability,
            component,
            severity,
            base_time + timedelta(days=1, seconds=index),
        ))

    with destination.open("w", encoding="utf-8", newline="") as output:
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow((
            "Agent", "CVE_ID", "Severity", "CVE_Description",
            "Affected_Product", "References", "OS_name", "Detected_At",
        ))
        for asset, vulnerability, component, severity, detected_at in observations:
            writer.writerow((
                f"agent-{asset + 1}",
                cve(vulnerability),
                severity,
                f"Reference vulnerability {cve(vulnerability)}",
                f"package-{asset + 1}-{component + 1}",
                f"https://security.example.test/{cve(vulnerability)}",
                "Debian 13",
                detected_at.isoformat().replace("+00:00", "Z"),
            ))

    print(destination.resolve())


if __name__ == "__main__":
    main()
