#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
reachability = (ROOT / "src/main/java/io/rbvm/context/FindingReachabilityScopeLink.java").read_text(encoding="utf-8")
service = (ROOT / "src/main/java/io/rbvm/context/FindingBusinessServiceLink.java").read_text(encoding="utf-8")
doc = (ROOT / "docs/FINDING_CONTEXT_ASSOCIATION_V1.md").read_text(encoding="utf-8")
builder = (ROOT / "src/main/java/io/rbvm/postgres/PostgresDecisionInputSnapshotBuilder.java").read_text(encoding="utf-8")

for needle in (
    "FINDING_REACHABILITY_SCOPE_LINK_V1",
    "CUSTOMER_CONFIRMED",
    "LINKED",
    "UNLINKED",
    "OriginScope",
    "TransportProtocol",
    "scopeKey",
    "evidenceSha256",
    "NFKC",
):
    if needle not in reachability:
        raise AssertionError(f"finding reachability link contract missing {needle!r}")

for needle in (
    "FINDING_BUSINESS_SERVICE_LINK_V1",
    "CUSTOMER_CONFIRMED",
    "LINKED",
    "UNLINKED",
    "businessService",
    "evidenceSha256",
    "NFKC",
):
    if needle not in service:
        raise AssertionError(f"finding business-service link contract missing {needle!r}")

for forbidden in (
    "AUTO_MATCH",
    "AUTO_LINK",
    "CVSS_SCORE",
    "EPSS_THRESHOLD",
    "RISK_SCORE",
    "PRIORITY_TIER",
):
    if forbidden in reachability or forbidden in service:
        raise AssertionError(f"finding context association domain contains forbidden heuristic/scoring construct {forbidden!r}")

for needle in (
    "RBVM_POLICY",
    "Finding-specific",
    "Customer-confirmed only",
    "Never assessed is not unlinked",
    "No heuristics",
    "Stable target, refreshed evidence",
    "Evidence source remains independent",
    "As-of semantics",
    "Exact binding provenance",
    "Target_Service",
    "Evidence_Source",
    "FINDING_REACHABILITY_SCOPE_LINK_EVENT",
    "FINDING_BUSINESS_SERVICE_LINK_EVENT",
    "Decision Input",
    "no `UPDATE / DELETE / TRUNCATE`",
    "Formula, Risk, Priority, SLA",
):
    if needle.lower() not in doc.lower():
        raise AssertionError(f"finding context association documentation missing {needle!r}")

# Guard the known pre-V3 gap explicitly: the builder still resolves a Finding without component_id
# and currently queries Reachability/Business Impact by asset_id. This verifier must be updated by
# the Decision Input V3 increment rather than allowing the gap to disappear without a contract.
if "SELECT asset_id, vulnerability_id" not in builder:
    raise AssertionError("Decision Input builder FindingScope changed; review association-readiness contract")
if "AND e.asset_id = ?" not in builder:
    raise AssertionError("Decision Input builder scoped-context query changed; review association-readiness contract")

print("Finding context association V1 structural checks: PASS")
