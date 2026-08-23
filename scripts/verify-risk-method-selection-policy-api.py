#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
api = (ROOT / "src/main/java/io/rbvm/csv/RiskMethodSelectionPolicyApi.java").read_text()
router = (ROOT / "src/main/java/io/rbvm/csv/RiskMethodSelectionPolicyHttpRouter.java").read_text()
runtime = (ROOT / "src/main/java/io/rbvm/postgres/RiskMethodSelectionPolicyRuntimeFactory.java").read_text()
server = (ROOT / "src/main/java/io/rbvm/csv/CsvPlatformServer.java").read_text()
api_test = (ROOT / "src/test/java/io/rbvm/csv/RiskMethodSelectionPolicyApiSelfTest.java").read_text()
http_test = (ROOT / "src/test/java/io/rbvm/csv/CsvRiskMethodSelectionPolicyHttpSelfTest.java").read_text()
openapi = (ROOT / "api/risk-method-selection-policy-v1.openapi.yaml").read_text()
doc = (ROOT / "docs/RISK_METHOD_SELECTION_POLICY_API_V1.md").read_text()
platform = (ROOT / "src/test/java/io/rbvm/csv/PlatformSelfTest.java").read_text()

for marker in [
    'RBVM_RISK_METHOD_SELECTION_POLICY_API_V1',
    'RBVM_RISK_METHOD_SELECTION_POLICY_INSTALLATION_API_V1',
    'EXACT_REVISION_AND_SHA_NO_CURRENT_LATEST_OR_DEFAULT',
    'RbvmRiskMethodSelectionPolicy.formulaV1',
    'RbvmRiskMethodSelectionPolicy.derived',
    'RISK_METHOD_SELECTION_POLICY_REVISION_CONFLICT',
    'strongEtag',
    'Location',
]:
    assert marker in api, f"risk method policy API missing {marker!r}"

for marker in [
    '/api/v1/risk-method-selection-policies/',
    '/api/v1/risk-method-selection-policy-installations/',
    'return ApiRole.VIEWER',
    'return ApiRole.OPERATOR',
    'routeAuthorized',
    'rejectQuery',
    'rejectBody',
]:
    assert marker in router, f"risk method policy router missing {marker!r}"

for marker in [
    'REQUIRED_SCHEMA_VERSION = 25',
    'PostgresRiskMethodSelectionPolicyStore',
]:
    assert marker in runtime, f"risk method policy runtime missing {marker!r}"

for marker in [
    'enableRiskMethodSelectionPolicyApi',
    'RiskMethodSelectionPolicyHttpRouter.requiredRole(exchange, method)',
    'AuthPrincipal principal = authorize(exchange, requiredRole)',
    'RISK_METHOD_SELECTION_POLICY_PERSISTENCE_UNAVAILABLE',
    'Risk Method Selection Policy API requires PostgreSQL schema version 25 or newer',
    'riskMethodSelectionPolicyRuntime',
    'rbvm_risk_method_selection_policy_api_enabled',
    'riskMethodSelectionPolicies',
]:
    assert marker in server, f"server risk method policy wiring missing {marker!r}"

assert server.index('RiskMethodSelectionPolicyHttpRouter.requiredRole(exchange, method)') < server.index(
    'RISK_METHOD_SELECTION_POLICY_PERSISTENCE_UNAVAILABLE'
), 'RBAC must resolve before V25 capability availability is observed'

for marker in [
    'installationStatus").equals("INSERTED")',
    'installationStatus").equals("REPLAYED")',
    'RISK_METHOD_SELECTION_POLICY_REVISION_CONFLICT',
    'definition.methodologyId().toLowerCase()',
    'store.size() == 1',
]:
    assert marker in api_test, f"API self-test missing {marker!r}"

for marker in [
    'unauthenticatedRead.statusCode() == 401',
    'viewerRead.statusCode() == 503',
    'viewerWrite.statusCode() == 403',
    'operatorWrite.statusCode() == 503',
    'store.size() == 3',
    '?latest=true',
    'collection.statusCode() == 404',
    'rbvm_risk_method_selection_policy_api_enabled 1',
]:
    assert marker in http_test, f"HTTP self-test missing {marker!r}"

for marker in [
    '/api/v1/risk-method-selection-policies/{revision}/{policySha256}:',
    '/api/v1/risk-method-selection-policy-installations/{revision}/{methodFamily}/{methodId}/{methodVersion}/{methodSha256}:',
    'RBVM_FORMULA, STANDARD_DERIVED',
    'EXACT_REVISION_AND_SHA_NO_CURRENT_LATEST_OR_DEFAULT',
    'RBVM_RISK_METHOD_SELECTION_POLICY_API_V1',
]:
    assert marker in openapi, f"risk method policy OpenAPI missing {marker!r}"

normalized_doc = ' '.join(doc.split())
for marker in [
    'There is no `latest`, `current`, max-revision, or default lookup.',
    'The route accepts no request body and no query parameters.',
    'an unauthenticated caller receives `401`',
    'a `VIEWER` attempting installation receives `403`',
    'separate versioned, auditable activation contract',
    'their scores are never averaged',
]:
    assert marker in normalized_doc, f"risk method policy API documentation missing {marker!r}"

assert 'RiskMethodSelectionPolicyApiSelfTest.main(args);' in platform
assert 'CsvRiskMethodSelectionPolicyHttpSelfTest.main(args);' in platform

for text, name in [(api, 'api'), (router, 'router'), (runtime, 'runtime')]:
    lowered = text.lower()
    for forbidden in ['findlatest', 'findcurrent', 'defaultmethod', 'averagescore', 'prioritytier', 'sladays']:
        assert forbidden not in lowered, f"{name} contains forbidden implicit decision semantic {forbidden!r}"

print('Risk method selection policy API V1 structural checks: PASS')
