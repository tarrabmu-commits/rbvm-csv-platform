#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
reach = (ROOT / "src/main/java/io/rbvm/csv/FindingReachabilityScopeLinkApi.java").read_text(encoding="utf-8")
business = (ROOT / "src/main/java/io/rbvm/csv/FindingBusinessServiceLinkApi.java").read_text(encoding="utf-8")
router = (ROOT / "src/main/java/io/rbvm/csv/FindingContextAssociationHttpRouter.java").read_text(encoding="utf-8")
server = (ROOT / "src/main/java/io/rbvm/csv/CsvPlatformServer.java").read_text(encoding="utf-8")
factory = (ROOT / "src/main/java/io/rbvm/postgres/CanonicalProjectionFactory.java").read_text(encoding="utf-8")
test = (ROOT / "src/test/java/io/rbvm/csv/FindingContextAssociationApiSelfTest.java").read_text(encoding="utf-8")
http_test = (ROOT / "src/test/java/io/rbvm/csv/CsvFindingContextAssociationHttpSelfTest.java").read_text(encoding="utf-8")
platform_test = (ROOT / "src/test/java/io/rbvm/csv/PlatformSelfTest.java").read_text(encoding="utf-8")

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

for needle in (
    "enableFindingContextAssociationApi",
    "FindingContextAssociationHttpRouter.inNamespace",
    "FINDING_CONTEXT_ASSOCIATION_PERSISTENCE_UNAVAILABLE",
    "rbvm_finding_context_association_api_enabled",
    "findingContextAssociations",
    "authorize(exchange, requiredRole)",
):
    if needle not in server:
        raise AssertionError(f"Finding-context server wiring is missing {needle!r}")

for needle in (
    "findingContextAssociationRuntimeFromEnvironment",
    "installedVersion < 21",
    "PostgresFindingReachabilityScopeLinkRegistry",
    "PostgresFindingBusinessServiceLinkRegistry",
    "FindingContextAssociationRuntime",
):
    if needle not in factory:
        raise AssertionError(f"Finding-context runtime factory is missing {needle!r}")

for needle in (
    'statusCode() == 401',
    'statusCode() == 403',
    'statusCode() == 503',
    'statusCode() == 412',
    '"frs-r0-',
    '"fbs-r0-',
    "NEVER_ASSESSED",
    "UNLINKED",
    "local-operator",
    "!reachZero.equals(otherZero)",
):
    if needle not in http_test:
        raise AssertionError(f"Finding-context socket self-test is missing proof {needle!r}")

if "CsvFindingContextAssociationHttpSelfTest.main(args);" not in platform_test:
    raise AssertionError("PlatformSelfTest must execute the Finding-context socket proof")

print("Finding context association API checks: PASS")
