#!/usr/bin/env python3
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
API = (ROOT / "src/main/java/io/rbvm/csv/DecisionInputApi.java").read_text(encoding="utf-8")
ROUTER = (ROOT / "src/main/java/io/rbvm/csv/DecisionInputHttpRouter.java").read_text(encoding="utf-8")
FORMULA_ROUTER = (ROOT / "src/main/java/io/rbvm/csv/FormulaResultHttpRouter.java").read_text(encoding="utf-8")
RUNTIME = (ROOT / "src/main/java/io/rbvm/postgres/DecisionInputRuntimeFactory.java").read_text(encoding="utf-8")
FORMULA_RUNTIME = (ROOT / "src/main/java/io/rbvm/postgres/FormulaResultRuntimeFactory.java").read_text(encoding="utf-8")
ACCESS = (ROOT / "src/main/java/io/rbvm/postgres/DecisionInputRuntimeAccess.java").read_text(encoding="utf-8")
SELF_TEST = (ROOT / "src/test/java/io/rbvm/csv/DecisionInputApiSelfTest.java").read_text(encoding="utf-8")
HTTP_SELF_TEST = (ROOT / "src/test/java/io/rbvm/csv/CsvDecisionInputHttpSelfTest.java").read_text(encoding="utf-8")
PLATFORM = (ROOT / "src/test/java/io/rbvm/csv/PlatformSelfTest.java").read_text(encoding="utf-8")
LIVE = (ROOT / "src/test/java/io/rbvm/postgres/PostgresV23FormulaResultLiveSelfTest.java").read_text(encoding="utf-8")
DOC = (ROOT / "docs/DECISION_INPUT_API_V1.md").read_text(encoding="utf-8")
OPENAPI_PATH = ROOT / "api/decision-input-v1.openapi.yaml"
OPENAPI = yaml.safe_load(OPENAPI_PATH.read_text(encoding="utf-8"))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


for marker in (
    'RBVM_DECISION_INPUT_API_V1',
    'RBVM_DECISION_INPUT_MATERIALIZATION_API_V1',
    'RBVM_DECISION_METHODOLOGY_CATALOG_API_V1',
    'getSnapshot(String snapshotSha256)',
    'history(',
    'methodologies(int limit, Integer afterRevision)',
    'getMethodology(int revision)',
    'materialize(String contentType, InputStream input)',
    '"findingId"',
    '"methodologyRevision"',
    '"methodologyPolicySha256"',
    '"evaluatedAt"',
    'DecisionInputSnapshotInstallResult.Status.INSERTED ? 201 : 200',
    '"Location"',
    'canonicalPayloadBase64',
    'evidenceReferences',
    'bindingSha256',
):
    require(marker in API, f"Decision Input API missing invariant {marker!r}")

for forbidden in (
    'priorityTier',
    'priorityScore',
    'slaDays',
    'treatmentDecision',
    'remediationDeadline',
    'relativeRiskIndex',
):
    require(forbidden not in API, f"Decision Input API contains forbidden field {forbidden!r}")

for marker in (
    '"/api/v1/decision-input-snapshots"',
    '"/api/v1/decision-input-materializations"',
    '"/api/v1/decision-methodologies"',
    '/decision-input-snapshots$',
    'return ApiRole.OPERATOR;',
    'return ApiRole.VIEWER;',
    'Set.of("limit", "beforeEvaluatedAt", "beforeSnapshotSha256")',
    'Set.of("limit", "afterRevision")',
    'beforeEvaluatedAt and beforeSnapshotSha256 must be supplied together',
):
    require(marker in ROUTER, f"Decision Input router missing invariant {marker!r}")

for forbidden in (
    'latest=',
    'current=',
    'preferred=',
    'priorityTier',
    'slaDays',
    'treatmentDecision',
):
    require(forbidden not in ROUTER, f"Decision Input router contains forbidden selector {forbidden!r}")

for marker in (
    'DecisionInputHttpRouter.inNamespace(path)',
    'DecisionInputHttpRouter.requiredRole(exchange, method)',
    'DecisionInputHttpRouter router = decisionInputs.orElseThrow',
    'DECISION_INPUT_RUNTIME_UNAVAILABLE',
    'translate(DecisionInputApi.ApiProblem problem)',
):
    require(marker in FORMULA_ROUTER,
            f"Formula transport missing Decision Input security bridge {marker!r}")

for marker in (
    'private static final int REQUIRED_SCHEMA_VERSION = 23;',
    'PostgresDecisionMethodologyPolicyStore',
    'PostgresDecisionInputSnapshotStore',
    'PostgresDecisionInputSnapshotBuilder',
    'DefaultDecisionInputSnapshotMaterializer',
    'PostgresDecisionInputHistoryReader',
    'PostgresDecisionMethodologyCatalog',
):
    require(marker in RUNTIME, f"Decision Input runtime factory missing {marker!r}")

require('DecisionInputSnapshotBuilder' not in FORMULA_RUNTIME,
        'Formula Result runtime must never directly own a Decision Input builder')
require('DecisionInputRuntimeFactory' in FORMULA_RUNTIME
        and '.fromEnvironment(environment)' in FORMULA_RUNTIME,
        'Formula workflow must consume the separate Decision Input runtime boundary')

for marker in (
    'MethodologyNotFoundException',
    'MethodologyIdentityMismatchException',
    'EvaluationConflictException',
    'if (!result.snapshot().isV3())',
    'stored.snapshotSha256().equals(result.snapshot().snapshotSha256())',
    'java.util.Arrays.equals(stored.canonicalPayload(), result.snapshot().canonicalPayload())',
):
    require(marker in ACCESS, f"Decision Input runtime access missing invariant {marker!r}")

for marker in (
    'readsExactSnapshotAndPreservesUnknownStates',
    'exposesHistoryAndMethodologyCatalogWithoutPrecedence',
    'materializesOnlyFromExplicitIdentityAndReplaysIdempotently',
    'rejectsInvalidMaterializationRequests',
    'first.status() == 201',
    'replay.status() == 200',
    '!history.body().containsKey("current")',
    '!history.body().containsKey("latest")',
    'DECISION_METHODOLOGY_IDENTITY_MISMATCH',
    'UNKNOWN_DECISION_INPUT_MATERIALIZATION_FIELDS',
):
    require(marker in SELF_TEST, f"Decision Input API self-test missing proof {marker!r}")

for marker in (
    'exposesExactReadsHistoryCatalogAndExplicitMaterialization',
    'rejectsHiddenSelectorsAndWrongMethods',
    'requiresOperatorBeforeDecisionInputCapabilityLookup',
    'inserted.statusCode() == 201',
    'replay.statusCode() == 200',
    'hidden.statusCode() == 400',
    'wrongMethod.statusCode() == 405',
    'unauthenticated.statusCode() == 401',
    'viewer.statusCode() == 403',
    'operator.statusCode() == 503',
    'DECISION INPUT RUNTIME UNAVAILABLE',
):
    require(marker in HTTP_SELF_TEST,
            f"Decision Input HTTP self-test missing proof {marker!r}")

require('DecisionInputApiSelfTest.main(args);' in PLATFORM,
        'Decision Input API self-test must run in PlatformSelfTest')
require('CsvDecisionInputHttpSelfTest.main(args);' in PLATFORM,
        'Decision Input HTTP self-test must run in PlatformSelfTest')

for marker in (
    'PostgresDecisionInputHistoryReader',
    'PostgresDecisionMethodologyCatalog',
    'DecisionInputRuntimeAccess decisionRuntime',
    'DecisionInputSnapshotInstallResult.Status.REPLAYED',
    'decisionReplay.snapshot().snapshotSha256().equals(snapshot.snapshotSha256())',
    'decision_history=PASS',
    'methodology_catalog=PASS',
    'decision_materialization_replay=PASS',
):
    require(marker in LIVE, f"V23 live suite missing Decision Input proof {marker!r}")

require(OPENAPI.get('openapi') == '3.0.3', 'Decision Input OpenAPI must declare 3.0.3')
paths = OPENAPI.get('paths', {})
expected_paths = {
    '/api/v1/decision-input-snapshots/{snapshotSha256}',
    '/api/v1/findings/{findingId}/decision-input-snapshots',
    '/api/v1/decision-input-materializations',
    '/api/v1/decision-methodologies',
    '/api/v1/decision-methodologies/{revision}',
}
require(set(paths) == expected_paths, 'Decision Input OpenAPI path set drifted')
require(set(paths['/api/v1/decision-input-materializations']) == {'post'},
        'Decision Input materialization must be POST-only')
for path in expected_paths - {'/api/v1/decision-input-materializations'}:
    require(set(paths[path]) == {'get'}, f'{path} must be GET-only')

request_schema = OPENAPI['components']['schemas']['MaterializationRequest']
require(request_schema.get('additionalProperties') is False,
        'Decision Input materialization body must reject unknown fields')
require(set(request_schema.get('required', [])) == {
    'findingId', 'methodologyRevision', 'methodologyPolicySha256', 'evaluatedAt'
}, 'Decision Input materialization body selectors drifted')

history_parameters = {
    item['name'] for item in
    paths['/api/v1/findings/{findingId}/decision-input-snapshots']['get']['parameters']
}
require(history_parameters == {
    'findingId', 'limit', 'beforeEvaluatedAt', 'beforeSnapshotSha256'
}, 'Decision Input history must expose only exact pagination selectors')
methodology_parameters = {
    item['name'] for item in paths['/api/v1/decision-methodologies']['get']['parameters']
}
require(methodology_parameters == {'limit', 'afterRevision'},
        'Methodology catalog must expose only pagination selectors')

openapi_text = OPENAPI_PATH.read_text(encoding='utf-8').lower()
for forbidden in ('latest:', 'current:', 'preferred:', 'prioritytier', 'sladays', 'treatmentdecision'):
    require(forbidden not in openapi_text,
            f'Decision Input OpenAPI contains forbidden selector/field {forbidden!r}')

for marker in (
    'POST /api/v1/decision-input-materializations',
    'GET /api/v1/decision-input-snapshots/{snapshotSha256}',
    'GET /api/v1/findings/{findingId}/decision-input-snapshots',
    'GET /api/v1/decision-methodologies',
    'GET /api/v1/decision-methodologies/{revision}',
    'no `current`, `latest`, `default`, or `preferred` methodology endpoint',
    'Priority',
    'Treatment',
    'SLA',
    'authorization is resolved before the runtime capability is looked up',
):
    require(marker.lower() in DOC.lower(), f"Decision Input API doc missing {marker!r}")

print('RBVM Decision Input HTTP/runtime/OpenAPI structural checks: PASS')
