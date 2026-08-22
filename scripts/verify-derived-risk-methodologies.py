#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

METHODS = (
    {
        "fixture": ROOT / "docs/fixtures/OWASP_DERIVED_RBVM_V1.json",
        "java": ROOT / "src/main/java/io/rbvm/decision/OwaspDerivedRiskV1.java",
        "contract": "OWASP_DERIVED_RBVM_V1",
        "sha": "03a72c8479e834174dc6985580d2543ad61b01628a79da5d59c5b5785e80c9c3",
        "provider": "OWASP",
        "equation": "Risk = Likelihood * Impact",
    },
    {
        "fixture": ROOT / "docs/fixtures/MICROSOFT_PD_DERIVED_RBVM_V1.json",
        "java": ROOT / "src/main/java/io/rbvm/decision/MicrosoftProbabilityDamageDerivedV1.java",
        "contract": "MICROSOFT_PD_DERIVED_RBVM_V1",
        "sha": "b22520b7b5a7d5f06782270feaf6729089ebafef79f20aea43dddf18396dcce6",
        "provider": "Microsoft",
        "equation": "Risk = Probability * Damage Potential",
    },
)

REQUIRED_DIMENSIONS = [
    "APPLICABILITY",
    "TECHNICAL_SEVERITY",
    "KNOWN_EXPLOITATION",
    "EXPLOITATION_PROBABILITY",
    "ASSET_CONTEXT",
    "NETWORK_REACHABILITY",
    "BUSINESS_MISSION_IMPACT",
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


for method in METHODS:
    raw = method["fixture"].read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    require(digest == method["sha"], f"fixture SHA mismatch: {method['fixture']}")

    data = json.loads(raw.decode("utf-8"))
    require(data["contractId"] == method["contract"], "contractId mismatch")
    require(data["version"] == 1, "derived methodology version must be 1")
    require(data["classification"] == "STANDARD_DERIVED", "classification must be STANDARD_DERIVED")
    require(data["provider"] == method["provider"], "provider mismatch")
    require(data["sourceEquation"] == method["equation"], "source equation mismatch")
    require(data["sourceUrl"].startswith("https://"), "source URL must use HTTPS")
    require(data["inputContractId"] == "RBVM_DECISION_INPUT_SNAPSHOT_V3", "input contract drift")
    require(data["requiredDimensions"] == REQUIRED_DIMENSIONS, "required dimension order drift")

    java = method["java"].read_text(encoding="utf-8")
    require(method["contract"] in java, f"Java contract ID missing: {method['java']}")
    require(method["sha"] in java, f"Java methodology SHA missing: {method['java']}")
    require("Classification.STANDARD_DERIVED" in java, "derived classification missing in Java")
    require(method["equation"] in java, f"source equation missing in Java: {method['java']}")

adapter = (ROOT / "src/main/java/io/rbvm/decision/RbvmDerivedRiskEvidence.java").read_text(
    encoding="utf-8"
)
require("RBVM_DECISION_INPUT_SNAPSHOT_V3" in adapter, "derived methods must require Decision Input V3")
require("DimensionState.MISSING" not in adapter, "unexpected direct DimensionState.MISSING token")
require("case MISSING, STALE, AMBIGUOUS" in adapter, "missing/stale/ambiguous gate must remain explicit")
require("BUSINESS_IMPACT_MULTI_SERVICE" in adapter, "cross-service business impact gate missing")
require("REACHABILITY_MULTI_SUBGRAIN" in adapter, "reachability ambiguity gate missing")
for forbidden in ("SELECT ", "current_", "latest", "preferred"):
    require(forbidden not in adapter, f"derived evidence adapter contains forbidden selector: {forbidden}")

catalog = (ROOT / "src/main/java/io/rbvm/decision/RbvmDerivedRiskMethodologyCatalog.java").read_text(
    encoding="utf-8"
)
require("MicrosoftProbabilityDamageDerivedV1.INSTANCE" in catalog, "Microsoft method missing from catalog")
require("OwaspDerivedRiskV1.INSTANCE" in catalog, "OWASP method missing from catalog")
require("default" not in catalog.lower(), "catalog must not define an implicit default methodology")

readme_doc = (ROOT / "docs/DERIVED_RISK_METHODOLOGIES_V1.md").read_text(encoding="utf-8")
require("official OWASP" in readme_doc, "OWASP derived disclosure missing")
require("Microsoft-produced score" in readme_doc, "Microsoft derived disclosure missing")
require("do not overwrite" in readme_doc, "historical Formula V1 preservation statement missing")

print("Derived risk methodologies structural checks: PASS")
