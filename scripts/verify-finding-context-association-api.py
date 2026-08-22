#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
reach = (ROOT / "src/main/java/io/rbvm/csv/FindingReachabilityScopeLinkApi.java").read_text(encoding="utf-8")
business = (ROOT / "src/main/java/io/rbvm/csv/FindingBusinessServiceLinkApi.java").read_text(encoding="utf-8")
router = (ROOT / "src/main/java/io/rbvm/csv/FindingContextAssociationHttpRouter.java").read_text(encoding="utf-8")
test = (ROOT / "src/test/java/io/rbvm/csv/FindingContextAssociationApiSelfTest.java").read_text(encoding="utf-8")

for name, text, prefix in (
    ("reachability API", reach, "frs"),
    ("business-service API", business, "fbs"),
):
    for needle in (
        "NEVER_ASSESSED",
        "If-Match",
        "PRECONDITION_REQUIRED",
        "PRECONDITION_FAILED",
        "FINDING_NOT_FOUND",
        "REVISION_CONFLICT",
        "REPLAYED",
        f'private static final String TAG_PREFIX = "{prefix}"',
        "FindingContextAssociationApiSupport.actor(actorId)",
    ):
        if needle not in text:
            raise AssertionError(f"{name} is missing {needle!r}")
    for forbidden in (
        "RISK_SCORE",
        "PRIORITY_TIER",
        "SLA_DAYS",
        "AUTO_LINK",
        "AUTO_MATCH",
        "CVSS_BASE_SCORE",
        "EPSS_PROBABILITY",
        "KNOWN_EXPLOITED",
    ):
        if forbidden in text:
            raise AssertionError(f"{name} must not contain {forbidden}")

for forbidden_body_actor in (
    '"changedBy", "changeNote"',
    '"changedBy"\n',
):
    if forbidden_body_actor in reach or forbidden_body_actor in business:
        raise AssertionError("Finding-context mutation bodies must not accept changedBy")

for needle in (
    "/api/v1/findings/",
    "reachability-links",
    "business-service-links",
    "ApiRole.VIEWER",
    "ApiRole.OPERATOR",
    "requireNoQuery(exchange)",
):
    if needle not in router:
        raise AssertionError(f"Finding-context HTTP router is missing {needle!r}")

for needle in (
    "different audit note",
    "REVISION_CONFLICT",
    "UNLINKED",
    "NEVER_ASSESSED",
    "changedBy",
    "FINDING_NOT_FOUND",
    "!zero.equals",
):
    if needle not in test:
        raise AssertionError(f"Finding-context API self-test is missing proof {needle!r}")

print("Finding context association API checks: PASS")
