#!/usr/bin/env python3
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
reach = (ROOT / "src/main/java/io/rbvm/csv/FindingReachabilityScopeLinkApi.java").read_text(encoding="utf-8")
business = (ROOT / "src/main/java/io/rbvm/csv/FindingBusinessServiceLinkApi.java").read_text(encoding="utf-8")
router = (ROOT / "src/main/java/io/rbvm/csv/FindingContextAssociationHttpRouter.java").read_text(encoding="utf-8")
server = (ROOT / "src/main/java/io/rbvm/csv/CsvPlatformServer.java").read_text(encoding="utf-8")
factory = (ROOT / "src/main/java/io/rbvm/postgres/CanonicalProjectionFactory.java").read_text(encoding="utf-8")
test = (ROOT / "src/test/java/io/rbvm/csv/FindingContextAssociationApiSelfTest.java").read_text(encoding="utf-8")
http_test = (ROOT / "src/test/java/io/rbvm/csv/CsvFindingContextAssociationHttpSelfTest.java").read_text(encoding="utf-8")
platform_test = (ROOT / "src/test/java/io/rbvm/csv/PlatformSelfTest.java").read_text(encoding="utf-8")
openapi_path = ROOT / "api/finding-context-association-v1.openapi.yaml"
openapi_text = openapi_path.read_text(encoding="utf-8")
openapi = yaml.safe_load(openapi_text)
base_openapi = yaml.safe_load((ROOT / "api/openapi.yaml").read_text(encoding="utf-8"))
composed_openapi = yaml.safe_load((ROOT / "api/openapi-v21.yaml").read_text(encoding="utf-8"))
resolved_openapi = yaml.safe_load(
    (ROOT / "api/resolved-active-risk-method-v1.openapi.yaml").read_text(encoding="utf-8")
)

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

if openapi.get("openapi") != "3.1.2":
    raise AssertionError("Finding-context OpenAPI must declare 3.1.2")
if openapi.get("security") != [{"bearerAuth": []}]:
    raise AssertionError("Finding-context OpenAPI must protect operations by default")

expected_paths = {
    "/findings/{findingId}/reachability-links",
    "/findings/{findingId}/reachability-links/current",
    "/findings/{findingId}/reachability-links/revisions",
    "/findings/{findingId}/business-service-links",
    "/findings/{findingId}/business-service-links/current",
    "/findings/{findingId}/business-service-links/revisions",
}
resolved_paths = {
    "/risk-method-selection-policy-activation/current/resolved",
    "/risk-method-selection-policy-activations/{activationRevision}/{eventSha256}/resolved",
}
if set(openapi.get("paths", {})) != expected_paths:
    raise AssertionError("Finding-context OpenAPI path set does not match the V1 router contract")

operation_ids = []
for path, item in openapi["paths"].items():
    for method, operation in item.items():
        if method not in {"get", "post"}:
            continue
        operation_id = operation.get("operationId")
        if not operation_id:
            raise AssertionError(f"{method.upper()} {path} lacks operationId")
        operation_ids.append(operation_id)
if len(operation_ids) != 8 or len(operation_ids) != len(set(operation_ids)):
    raise AssertionError("Finding-context OpenAPI must expose eight unique operations")

for path in (
    "/findings/{findingId}/reachability-links/current",
    "/findings/{findingId}/business-service-links/current",
):
    post = openapi["paths"][path]["post"]
    parameters = post.get("parameters", [])
    if not any(p.get("$ref") == "#/components/parameters/IfMatch" for p in parameters):
        raise AssertionError(f"POST {path} must require If-Match")
    responses = post.get("responses", {})
    for status in {"200", "400", "401", "403", "404", "412", "413", "415", "422", "428", "429", "503"}:
        if status not in responses:
            raise AssertionError(f"POST {path} lacks response {status}")

request_schemas = openapi["components"]["schemas"]
for name in ("ReachabilityRevisionRequest", "BusinessServiceRevisionRequest"):
    properties = request_schemas[name].get("properties", {})
    if "changedBy" in properties:
        raise AssertionError(f"{name} must not accept changedBy")

for needle in ("NEVER_ASSESSED", "CUSTOMER_CONFIRMED", "UNLINKED"):
    if needle not in openapi_text:
        raise AssertionError(f"Finding-context OpenAPI is missing {needle}")
for forbidden in ("riskScore", "priorityTier", "slaDays", "autoLink", "autoMatch"):
    if forbidden in openapi_text:
        raise AssertionError(f"Finding-context OpenAPI must not introduce {forbidden}")

if composed_openapi.get("openapi") != "3.1.2":
    raise AssertionError("Composed V21 OpenAPI must declare 3.1.2")
if composed_openapi.get("security") != [{"bearerAuth": []}]:
    raise AssertionError("Composed V21 OpenAPI must retain default bearer security")
if composed_openapi.get("info", {}).get("version") != base_openapi.get("info", {}).get("version"):
    raise AssertionError("Composed V21 OpenAPI version must match the published base contract")
base_paths = set(base_openapi.get("paths", {}))
composed_paths = set(composed_openapi.get("paths", {}))
if composed_paths != base_paths | expected_paths:
    missing = (base_paths | expected_paths) - composed_paths
    extra = composed_paths - (base_paths | expected_paths)
    raise AssertionError(
        f"Composed V21 OpenAPI path drift: missing={sorted(missing)}, extra={sorted(extra)}"
    )
for path, item in composed_openapi["paths"].items():
    reference = item.get("$ref")
    if not reference:
        raise AssertionError(f"Composed path {path} must be a source-contract reference")
    if path in expected_paths:
        source_name = "finding-context-association-v1.openapi.yaml"
        source_document = openapi
        expected_source_path = path
    elif path in resolved_paths:
        source_name = "resolved-active-risk-method-v1.openapi.yaml"
        source_document = resolved_openapi
        expected_source_path = "/api/v1" + path
    else:
        if path not in base_paths:
            raise AssertionError(f"Composed unowned path {path} is absent from base openapi.yaml")
        continue
    expected_prefix = f"./{source_name}#/paths/"
    if not reference.startswith(expected_prefix):
        raise AssertionError(f"Composed path {path} references the wrong source contract")
    pointer = reference[len(expected_prefix):]
    resolved_path = pointer.replace("~1", "/").replace("~0", "~")
    if resolved_path != expected_source_path:
        raise AssertionError(
            f"Composed path {path} resolves to a different source path {resolved_path}"
        )
    if resolved_path not in source_document.get("paths", {}):
        raise AssertionError(f"Composed path {path} resolves to a missing source path")

print("Finding context association API checks: PASS")
