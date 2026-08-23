#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
api = (ROOT / "src/main/java/io/rbvm/csv/RiskMethodSelectionPolicyApi.java").read_text()
router = (ROOT / "src/main/java/io/rbvm/csv/RiskMethodSelectionPolicyHttpRouter.java").read_text()
api_test = (ROOT / "src/test/java/io/rbvm/csv/ResolvedActiveRiskMethodApiSelfTest.java").read_text()
derived_test = (ROOT / "src/test/java/io/rbvm/csv/ResolvedActiveRiskMethodDerivedApiSelfTest.java").read_text()
http_test = (ROOT / "src/test/java/io/rbvm/csv/CsvResolvedActiveRiskMethodHttpSelfTest.java").read_text()
openapi = (ROOT / "api/resolved-active-risk-method-v1.openapi.yaml").read_text()
combined = (ROOT / "api/openapi.yaml").read_text()
composed = (ROOT / "api/openapi-v21.yaml").read_text()
doc = (ROOT / "docs/RESOLVED_ACTIVE_RISK_METHOD_API_V1.md").read_text()
platform = (ROOT / "src/test/java/io/rbvm/csv/PlatformSelfTest.java").read_text()
verify_sh = (ROOT / "scripts/verify.sh").read_text()

for marker in (
    'RBVM_RESOLVED_ACTIVE_RISK_METHOD_API_V1',
    'EXPLICIT_ACTIVATION_TO_EXACT_POLICY_TO_EXACT_METHOD_NO_DEFAULT',
    'resolvedCurrentSelection()',
    'resolvedActivation(int activationRevision, String eventSha256)',
    'policies.findByRevision(event.policyRevision())',
    '.filter(candidate -> candidate.policySha256().equals(event.policySha256()))',
    'RISK_METHOD_SELECTION_POLICY_ACTIVATION_INTEGRITY_FAILURE',
    'body.put("policy", null)',
    'body.put("selectedMethod", null)',
    'output.put("selectionRole", policy.selectionRole().name())',
    'output.put("methodFamily", policy.methodFamily().name())',
    'output.put("methodId", policy.methodId())',
    'output.put("methodVersion", policy.methodVersion())',
    'output.put("methodSha256", policy.methodSha256())',
    'activationStrongEtag(event.eventSha256())',
    'resolvedActivationLocation(event)',
):
    assert marker in api, f"resolved active risk method API missing {marker!r}"

for marker in (
    '/api/v1/risk-method-selection-policy-activation/current/resolved',
    'ACTIVATION_RESOLVED_ITEM',
    'api.resolvedCurrentSelection()',
    'api.resolvedActivation(',
    'return ApiRole.VIEWER',
    'rejectQuery(exchange)',
    'rejectBody(exchange, "Resolved current activation read does not accept a request body")',
    'rejectBody(exchange, "Resolved exact activation read does not accept a request body")',
):
    assert marker in router, f"resolved active risk method router missing {marker!r}"

for marker in (
    'selectionState").equals("ACTIVE")',
    'selectionState").equals("CLEARED")',
    'resolved.body().get("policy") == null',
    'resolved.body().get("selectedMethod") == null',
    'RISK_METHOD_SELECTION_POLICY_ACTIVATION_INTEGRITY_FAILURE',
    'RISK_METHOD_SELECTION_POLICY_ACTIVATION_PERSISTENCE_UNAVAILABLE',
    'resolvedActivation(7, eventSha)',
    'resolvedActivation(7, "0".repeat(64))',
    'method.get("methodSha256").equals(RbvmFormulaV1.FORMULA_SHA256)',
):
    assert marker in api_test, f"resolved API self-test missing {marker!r}"

for marker in (
    'RbvmDerivedRiskMethodologyCatalog.definitions()',
    'RbvmRiskMethodSelectionPolicy.derived(1, definition)',
    'selectedMethod.get("methodFamily").equals("STANDARD_DERIVED")',
    'selectedMethod.get("methodId").equals(definition.methodologyId())',
    'selectedMethod.get("methodVersion").equals(definition.version())',
    'selectedMethod.get("methodSha256").equals(definition.methodologySha256())',
):
    assert marker in derived_test, f"resolved derived API self-test missing {marker!r}"

for marker in (
    '/api/v1/risk-method-selection-policy-activation/current/resolved',
    '/api/v1/risk-method-selection-policy-activations/7/',
    'RBVM_RESOLVED_ACTIVE_RISK_METHOD_API_V1',
    'EXPLICIT_ACTIVATION_TO_EXACT_POLICY_TO_EXACT_METHOD_NO_DEFAULT',
    '?latest=true',
    'wrongMethod.statusCode() == 405',
    'unauthenticated.statusCode() == 401',
    'viewer.statusCode() == 503',
    '\"policy\": null',
    '\"selectedMethod\": null',
):
    assert marker in http_test, f"resolved HTTP self-test missing {marker!r}"

for marker in (
    '/api/v1/risk-method-selection-policy-activation/current/resolved:',
    '/api/v1/risk-method-selection-policy-activations/{activationRevision}/{eventSha256}/resolved:',
    'RBVM_RESOLVED_ACTIVE_RISK_METHOD_API_V1',
    'EXPLICIT_ACTIVATION_TO_EXACT_POLICY_TO_EXACT_METHOD_NO_DEFAULT',
    'enum: [ACTIVE, CLEARED]',
    'nullable: true',
    'IntegrityFailure',
    'selectedMethod',
):
    assert marker in openapi, f"resolved OpenAPI missing {marker!r}"

for marker in (
    '/risk-method-selection-policy-activation/current/resolved:',
    '/risk-method-selection-policy-activations/{activationRevision}/{eventSha256}/resolved:',
    "./resolved-active-risk-method-v1.openapi.yaml#",
):
    assert marker in combined, f"combined OpenAPI missing resolved route {marker!r}"
    assert marker in composed, f"composed OpenAPI missing resolved route {marker!r}"

normalized_doc = ' '.join(doc.split())
for marker in (
    'current is operational discovery only',
    '`activation.activationRevision`',
    '`activation.eventSha256`',
    'Never-activated is not synthesized as CLEARED.',
    '`selectionState = CLEARED`',
    '`policy = null`',
    '`selectedMethod = null`',
    'fails closed with `500 RISK_METHOD_SELECTION_POLICY_ACTIVATION_INTEGRITY_FAILURE`',
    'no: - activation collection/list',
    'Priority, Treatment, SLA, remediation deadline',
):
    assert marker in normalized_doc, f"resolved API documentation missing {marker!r}"

assert 'ResolvedActiveRiskMethodApiSelfTest.main(args);' in platform
assert 'ResolvedActiveRiskMethodDerivedApiSelfTest.main(args);' in platform
assert 'CsvResolvedActiveRiskMethodHttpSelfTest.main(args);' in platform
assert 'verify-resolved-active-risk-method.py' in verify_sh

# This projection must not add a database version or separate runtime capability.
assert 'V27__' not in api + router
assert 'ResolvedActiveRiskMethodRuntimeFactory' not in api + router

for text, name in ((api, 'api'), (router, 'router')):
    lowered = text.lower()
    for forbidden in (
        'findlatest',
        'maxpolicy',
        'defaultmethod',
        'preferredmethod',
        'fallbackmethod',
        'averagescore',
        'prioritytier',
        'priorityscore',
        'sladays',
        'treatmentdecision',
        'remediationdeadline',
    ):
        assert forbidden not in lowered, f"{name} contains forbidden implicit semantic {forbidden!r}"

print('Resolved active risk method API V1 structural checks: PASS')
