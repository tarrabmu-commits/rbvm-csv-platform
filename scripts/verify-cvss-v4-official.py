#!/usr/bin/env python3
"""Verify the local CVSS v4 engine against FIRST-published examples."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cvss_v4_official import CvssV4Error, score_record  # noqa: E402

CASES = [
    ("CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.3, "CVSS-B"),
    ("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U", 5.2, "CVSS-BT"),
    ("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/MAC:L/MAT:N/MVC:N/MVI:N/MVA:L", 5.5, "CVSS-BTE"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3, "CVSS-B"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A", 10.0, "CVSS-BT"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0, "CVSS-B"),
]

for vector, expected_score, expected_mode in CASES:
    result = score_record(vector)
    if result["score"] != expected_score or result["nomenclature"] != expected_mode:
        raise AssertionError(f"FIRST example mismatch: {vector} -> {result}")

# FIRST scoring semantics: E:X is score-equivalent to E:A, but an omitted
# Threat group remains CVSS-B nomenclature rather than being relabeled BT.
base = score_record("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
attacked = score_record("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A")
if base["score"] != attacked["score"] or base["nomenclature"] != "CVSS-B" or attacked["nomenclature"] != "CVSS-BT":
    raise AssertionError("E:X/E:A default or nomenclature semantics are wrong")

try:
    score_record("CVSS:4.0/AV:N/AC:L")
except CvssV4Error:
    pass
else:
    raise AssertionError("incomplete Base vector must be rejected")

print(f"CVSS v4 official-engine checks: PASS examples={len(CASES)}")
