#!/usr/bin/env python3
"""Verify the canonical CISA BOD 26-04 remediation-priority foundation."""

from __future__ import annotations

import importlib.util
from itertools import product
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "cisa_bod_26_04.py"
DOC_PATH = ROOT / "docs" / "CISA_BOD_26_04_REMEDIATION_PRIORITY_V1.md"
EXPECTED_SHA = "64066ae687fd98c6db48fa224316446dc579737ff6c16321f155de69c5f0e9ff"


def load_module():
    spec = importlib.util.spec_from_file_location("cisa_bod_26_04", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load CISA BOD 26-04 module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    module = load_module()

    assert module.METHOD_ID == "CISA_BOD_26_04_REMEDIATION_PRIORITY_METHOD_V1"
    assert module.SOURCE_DECISION_TABLE_ID == "cisa:DT_BOD2604:1.0.0"
    assert module.SOURCE_OUTCOME_GROUP_ID == "cisa:BOD2604:1.0.0"
    assert module.IN_KEV_ID == "cisa:KEV:1.0.0"
    assert module.PUBLICLY_EXPOSED_ID == "cisa:PE:1.0.0"
    assert module.AUTOMATABLE_ID == "ssvc:A:2.0.0"
    assert module.TECHNICAL_IMPACT_ID == "ssvc:TI:1.0.0"
    assert module.METHOD_SHA256 == EXPECTED_SHA
    assert module.EXPECTED_METHOD_SHA256 == EXPECTED_SHA

    expected = {
        ("N", "N", "N", "P"): "FSU",
        ("Y", "N", "N", "P"): "14D",
        ("N", "Y", "N", "P"): "60D",
        ("N", "N", "Y", "P"): "60D",
        ("N", "N", "N", "T"): "FSU",
        ("Y", "Y", "N", "P"): "14D",
        ("Y", "N", "Y", "P"): "14D",
        ("N", "Y", "Y", "P"): "14D",
        ("Y", "N", "N", "T"): "14D",
        ("N", "Y", "N", "T"): "14D",
        ("N", "N", "Y", "T"): "60D",
        ("Y", "Y", "Y", "P"): "3D",
        ("Y", "Y", "N", "T"): "3DF",
        ("Y", "N", "Y", "T"): "3DF",
        ("N", "Y", "Y", "T"): "3D",
        ("Y", "Y", "Y", "T"): "3DF",
    }
    assert len(module.TABLE_ROWS) == 16
    assert len(expected) == 16
    assert set(module.OUTCOMES) == {"FSU", "60D", "14D", "3D", "3DF"}

    all_vectors = set(product(("N", "Y"), ("N", "Y"), ("N", "Y"), ("P", "T")))
    assert set(expected) == all_vectors
    for key, outcome in expected.items():
        assert module.lookup(*key) == outcome, (key, outcome)

    try:
        module.lookup("", "N", "N", "P")
        raise AssertionError("incomplete vector must be rejected")
    except ValueError:
        pass

    yes_auto = module.resolve_automatable("Yes")
    no_auto = module.resolve_automatable("no")
    missing_auto = module.resolve_automatable("")
    unknown_auto = module.resolve_automatable("UNKNOWN")
    invalid_auto = module.resolve_automatable("maybe")
    assert (yes_auto.status, yes_auto.value) == ("PRESENT", "Y")
    assert (no_auto.status, no_auto.value) == ("PRESENT", "N")
    assert (missing_auto.status, missing_auto.value, missing_auto.blocker) == (
        "MISSING", None, "AUTOMATABLE_MISSING"
    )
    assert (unknown_auto.status, unknown_auto.value, unknown_auto.blocker) == (
        "MISSING", None, "AUTOMATABLE_MISSING"
    )
    assert (invalid_auto.status, invalid_auto.value, invalid_auto.blocker) == (
        "INVALID", None, "AUTOMATABLE_INVALID"
    )

    partial = module.resolve_technical_impact("Partial")
    total = module.resolve_technical_impact("T")
    missing_ti = module.resolve_technical_impact(None)
    incomplete_ti = module.resolve_technical_impact("INCOMPLETE")
    invalid_ti = module.resolve_technical_impact("high")
    assert (partial.status, partial.value) == ("PRESENT", "P")
    assert (total.status, total.value) == ("PRESENT", "T")
    assert missing_ti.status == "MISSING" and missing_ti.value is None
    assert incomplete_ti.status == "MISSING" and incomplete_ti.value is None
    assert invalid_ti.status == "INVALID" and invalid_ti.value is None

    # Explicit Publicly Exposed is a distinct BOD input. UNKNOWN/missing is not No.
    assert module.resolve_publicly_exposed("YES").value == "Y"
    assert module.resolve_publicly_exposed("NO").value == "N"
    assert module.resolve_publicly_exposed("UNKNOWN").status == "MISSING"
    assert module.resolve_publicly_exposed("").status == "MISSING"
    assert module.resolve_publicly_exposed("maybe").status == "INVALID"

    # KEV resolution only accepts an already established membership state.
    assert module.resolve_in_kev("LISTED").value == "Y"
    assert module.resolve_in_kev("NOT_LISTED").value == "N"
    assert module.resolve_in_kev("").status == "MISSING"
    assert module.resolve_in_kev("UNKNOWN").status == "MISSING"
    assert module.resolve_in_kev("maybe").status == "INVALID"

    canonical_text = module.CANONICAL_JSON.casefold()
    for forbidden in (
        "epss", "cvss", "assetcriticality", "asset_criticality", "businessimpact", "business_impact",
        "internetfacing", "internet_facing", "low", "medium", "high", "critical",
    ):
        assert forbidden not in canonical_text, f"forbidden non-BOD/presentation input in canonical method: {forbidden}"

    document = DOC_PATH.read_text(encoding="utf-8")
    for required in (
        "cisa:DT_BOD2604:1.0.0",
        "cisa:BOD2604:1.0.0",
        "cisa:PE:1.0.0",
        "ssvc:A:2.0.0",
        "ssvc:TI:1.0.0",
        "internetFacing=YES",
        "INCOMPLETE",
        "RBVM_MVP_PRIORITY_POLICY_V1",
        EXPECTED_SHA,
    ):
        assert required in document, f"documentation missing required boundary: {required}"

    print("CISA BOD 26-04 remediation-priority foundation: PASS")


if __name__ == "__main__":
    main()
