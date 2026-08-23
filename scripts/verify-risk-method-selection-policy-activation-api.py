#!/usr/bin/env python3
from pathlib import Path
import re
import yaml

ROOT = Path(__file__).resolve().parents[1]
api = (ROOT / "src/main/java/io/rbvm/csv/RiskMethodSelectionPolicyApi.java").read_text()
router = (ROOT / "src/main/java/io/rbvm/csv/RiskMethodSelectionPolicyHttpRouter.java").read_text()
store_api = (ROOT / "src/main/java/io/rbvm/postgres/RiskMethodSelectionPolicyStore.java").read_text()
runtime = (ROOT / "src/main/java/io/rbvm/postgres/RiskMethodSelectionPolicyRuntimeFactory.java").read_text()
api_test = (ROOT / "src/test/java/io/rbvm/csv/RiskMethodSelectionPolicyActivationApiSelfTest.java").read_text()
http_test = (ROOT / "src/test/java/io/rbvm/csv/CsvRiskMethodSelectionPolicyActivationHttpSelfTest.java").read_text()
dedicated_path = ROOT / "api/risk-method-selection-policy-activation-v1.openapi.yaml"
combined_path = ROOT / "api/openapi.yaml"
composed_path = ROOT / "api/openapi-v21.yaml"
dedicated = dedicated_path.read_text()
combined = combined_path.read_text()
composed = composed_path.read_text()
doc = (ROOT / "docs/RISK_METHOD_SELECTION_POLICY_ACTIVATION_API_V1.md").read_text()
platform = (ROOT / "src/test/java/io/rbvm/csv/PlatformSelfTest.java").read_text()
verify = (ROOT / "scripts/verify.sh").read_text()

routes = (
    "/risk-method-selection-policy-activation/current",
    "/risk-method-selection-policy-activations/{activationRevision}/{eventSha256}",
    "/risk-method-selection-policy-activation-events/{activationRevision}/ACTIVE/{policyRevision}/{policySha256}/{recordedAt}",
    "/risk-method-selection-policy-activation-events/{activationRevision}/CLEARED/{recordedAt}",
)
dedicated_routes = tuple("/api/v1" + route for route in routes)

for marker in (
    "RBVM_RISK_METHOD_SELECTION_POLICY_ACTIVATION_API_V1",
    "RBVM_RISK_METHOD_SELECTION_POLICY_ACTIVATION_INSTALLATION_API_V1",
    "CURRENT_IS_GREATEST_EXPLICIT_ACTIVATION_REVISION_NEVER_POLICY_REVISION",
    "currentActivation()",
    "getActivation(int activationRevision, String eventSha256)",
    "activate(",
    "clearActivation(",
    "RISK_METHOD_SELECTION_POLICY_ACTIVATION_PERSISTENCE_UNAVAILABLE",
    "RISK_METHOD_SELECTION_POLICY_ACTIVATION_REVISION_CONFLICT",
    "STALE_RISK_METHOD_SELECTION_POLICY_ACTIVATION_REVISION",
    "RISK_METHOD_SELECTION_POLICY_NOT_FOUND",
    "activationStrongEtag",
    "activationLocation",
    "canonicalPayloadBase64",
):
    assert marker in api, f"activation API missing {marker!r}"

for marker in (
    'return policies.activationStore().orElseThrow',
    'policies.findByRevision(exactPolicyRevision)',
    'candidate.policySha256().equals(exactPolicySha)',
    'RbvmRiskMethodSelectionPolicyActivationEvent.activate',
    'RbvmRiskMethodSelectionPolicyActivationEvent.clear',
):
    assert marker in api, f"activation exact-identity guard missing {marker!r}"

for marker in (
    'default Optional<RiskMethodSelectionPolicyActivationStore> activationStore()',
    'return Optional.empty();',
):
    assert marker in store_api, f"V25-compatible activation capability boundary missing {marker!r}"

for marker in (
    "ACTIVATION_SCHEMA_VERSION = 26",
    "installedVersion >= ACTIVATION_SCHEMA_VERSION",
    "PostgresRiskMethodSelectionPolicyActivationStore",
    "PolicyStoreWithActivation",
    "Optional.of(activations)",
):
    assert marker in runtime, f"activation runtime wiring missing {marker!r}"

for marker in (
    "/api/v1/risk-method-selection-policy-activation/current",
    "/api/v1/risk-method-selection-policy-activations/",
    "/api/v1/risk-method-selection-policy-activation-events/",
    "ACTIVE_EVENT",
    "CLEARED_EVENT",
    "return ApiRole.VIEWER",
    "return ApiRole.OPERATOR",
    "principal.actorId()",
    "Instant.parse(value)",
    "rejectQuery(exchange)",
    "rejectBody(exchange",
):
    assert marker in router, f"activation HTTP router missing {marker!r}"

assert router.index("requiredRole(HttpExchange exchange, String method)") < router.index(
    "routeAuthorized(HttpExchange exchange, String method, AuthPrincipal principal)"
), "router must preserve route-level RBAC resolution before authorized activation execution"

for marker in (
    "activatesReadsReplaysAndClearsExactPolicy",
    "distinguishesNeverActivatedFromCleared",
    "rejectsMissingConflictAndStaleIdentities",
    "protectsV25PolicyRuntimeWithoutV26Activation",
    'installationStatus").equals("REPLAYED")',
    "RISK_METHOD_SELECTION_POLICY_ACTIVATION_NOT_FOUND",
    "RISK_METHOD_SELECTION_POLICY_ACTIVATION_REVISION_CONFLICT",
    "STALE_RISK_METHOD_SELECTION_POLICY_ACTIVATION_REVISION",
):
    assert marker in api_test, f"activation API self-test missing {marker!r}"

for marker in (
    "activatesReplaysReadsAndClearsExactEvents",
    "rejectsImplicitOrMalformedActivationSelectors",
    "protectsV26CapabilityBehindAuthorization",
    "unauthenticatedRead.statusCode() == 401",
    "viewerRead.statusCode() == 503",
    "viewerWrite.statusCode() == 403",
    "operatorWrite.statusCode() == 503",
    "never.statusCode() == 404",
    "currentCleared.statusCode() == 200",
    "conflictResponse.statusCode() == 409",
    "staleResponse.statusCode() == 409",
    "?latest=true",
    "collection.statusCode() == 404",
):
    assert marker in http_test, f"activation HTTP self-test missing {marker!r}"

with dedicated_path.open(encoding="utf-8") as handle:
    dedicated_yaml = yaml.safe_load(handle)
with combined_path.open(encoding="utf-8") as handle:
    combined_yaml = yaml.safe_load(handle)
with composed_path.open(encoding="utf-8") as handle:
    composed_yaml = yaml.safe_load(handle)

for route in dedicated_routes:
    assert route in dedicated_yaml["paths"], f"dedicated activation OpenAPI missing {route}"
for route in routes:
    assert route in combined_yaml["paths"], f"combined OpenAPI missing {route}"
    assert route in composed_yaml["paths"], f"composed OpenAPI missing {route}"

assert "/api/v1/risk-method-selection-policy-activations" not in dedicated_yaml["paths"], (
    "dedicated OpenAPI must not expose an activation collection/list route"
)
assert "/risk-method-selection-policy-activations" not in combined_yaml["paths"], (
    "combined OpenAPI must not expose an activation collection/list route"
)

for marker in (
    "RBVM_RISK_METHOD_SELECTION_POLICY_ACTIVATION_API_V1",
    "CURRENT_IS_GREATEST_EXPLICIT_ACTIVATION_REVISION_NEVER_POLICY_REVISION",
    "Never-activated",
    "explicit ISO-8601 `recordedAt`",
    "changedBy` is taken from the authenticated principal",
    "No command auto-increments a revision",
    "V25 policy persistence remains available on PostgreSQL schema 25",
    "activation transport requires V26",
    "browser activation control",
    "Priority, Treatment, SLA",
):
    assert marker.lower() in doc.lower(), f"activation API documentation missing {marker!r}"

production = "\n".join((api, router, store_api, runtime))
for forbidden_pattern in (
    r"activationRevision\s*\+\s*1",
    r"policyRevision\s*\+\s*1",
    r"maxPolicyRevision",
    r"findLatestPolicy",
    r"defaultMethod",
    r"preferredMethod",
    r"averageScore",
    r"priorityTier",
    r"slaDays",
    r"treatmentDecision",
):
    assert not re.search(forbidden_pattern, production, re.IGNORECASE), (
        f"activation production code contains forbidden implicit semantic {forbidden_pattern!r}"
    )

assert "RiskMethodSelectionPolicyActivationApiSelfTest.main(args);" in platform
assert "CsvRiskMethodSelectionPolicyActivationHttpSelfTest.main(args);" in platform
assert 'python3 "$ROOT_DIR/scripts/verify-risk-method-selection-policy-activation-api.py"' in verify

for marker in (
    "RBVM_RISK_METHOD_SELECTION_POLICY_ACTIVATION_API_V1",
    "ACTIVE",
    "CLEARED",
    "recordedAt",
    "INSERTED, REPLAYED",
):
    assert marker in dedicated, f"dedicated activation OpenAPI text missing {marker!r}"

print("Risk Method Selection Policy Activation API V1 structural checks: PASS")
