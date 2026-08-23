#!/usr/bin/env python3
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
API = (ROOT / 'src/main/java/io/rbvm/csv/ActiveRiskMethodExecutionApi.java').read_text(encoding='utf-8')
ROUTER = (ROOT / 'src/main/java/io/rbvm/csv/ActiveRiskMethodExecutionHttpRouter.java').read_text(encoding='utf-8')
RUNTIME = (ROOT / 'src/main/java/io/rbvm/postgres/ActiveRiskMethodExecutionRuntimeFactory.java').read_text(encoding='utf-8')
SERVER = (ROOT / 'src/main/java/io/rbvm/csv/CsvPlatformServer.java').read_text(encoding='utf-8')
API_TEST = (ROOT / 'src/test/java/io/rbvm/csv/ActiveRiskMethodExecutionApiSelfTest.java').read_text(encoding='utf-8')
HTTP_TEST = (ROOT / 'src/test/java/io/rbvm/csv/CsvActiveRiskMethodExecutionHttpSelfTest.java').read_text(encoding='utf-8')
PLATFORM = (ROOT / 'src/test/java/io/rbvm/csv/PlatformSelfTest.java').read_text(encoding='utf-8')
DOC = (ROOT / 'docs/ACTIVE_RISK_METHOD_EXECUTION_API_V1.md').read_text(encoding='utf-8')
SPEC_PATH = ROOT / 'api/active-risk-method-execution-v1.openapi.yaml'
SPEC = yaml.safe_load(SPEC_PATH.read_text(encoding='utf-8'))
COMBINED = (ROOT / 'api/openapi.yaml').read_text(encoding='utf-8')
COMPOSED = (ROOT / 'api/openapi-v21.yaml').read_text(encoding='utf-8')
VERIFY_SH = (ROOT / 'scripts/verify.sh').read_text(encoding='utf-8')


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


for marker in (
    'RBVM_ACTIVE_RISK_METHOD_EXECUTION_API_V1',
    'EXPLICIT_ACTIVATION_REVISION_EVENT_SHA_AND_DECISION_INPUT_SHA_ONLY_NO_CURRENT_DEFAULT',
    'execute(',
    'activationRevision',
    'activationEventSha256',
    'inputSnapshotSha256',
    'materializer.materialize(activationRevision, eventSha, inputSha)',
    'RISK_METHOD_SELECTION_ACTIVATION_CLEARED',
    'SELECTED_RISK_METHOD_UNAVAILABLE',
    'ACTIVE_RISK_METHOD_EXECUTION_REQUIRES_DECISION_INPUT_V3',
    'ACTIVE_RISK_METHOD_EXECUTION_CONFLICT',
    'ACTIVE_RISK_METHOD_EXECUTION_INTEGRITY_FAILURE',
    'findByBindingSha256',
    'canonicalPayloadBase64',
    'resultLocation',
    '/api/v1/formula-results/',
    '/api/v1/derived-risk-results/',
):
    require(marker in API, f'active risk execution API missing invariant {marker!r}')

for forbidden in (
    'currentActivation(',
    'resolvedCurrentSelection(',
    'findLatest',
    'findCurrent',
    'priorityTier',
    'priorityScore',
    'slaDays',
    'treatmentDecision',
    'remediationDeadline',
    'averageScore',
):
    require(forbidden not in API,
            f'active risk execution API contains forbidden construct {forbidden!r}')

for marker in (
    '"/api/v1/active-risk-method-executions"',
    '"/api/v1/active-risk-method-execution-bindings"',
    'EXECUTION_ITEM',
    'BINDING_ITEM',
    'return ApiRole.OPERATOR;',
    'return ApiRole.VIEWER;',
    '"POST"',
    '"GET"',
    'INVALID_ACTIVE_RISK_METHOD_EXECUTION_QUERY',
    'ACTIVE_RISK_METHOD_EXECUTION_BODY_NOT_ALLOWED',
    'api.execute(',
    'api.getBinding(',
):
    require(marker in ROUTER, f'active risk execution router missing invariant {marker!r}')

for forbidden in (
    '/current',
    'latest=true',
    'current=true',
    'localStorage',
    'sessionStorage',
    'priorityTier',
    'slaDays',
):
    require(forbidden not in ROUTER,
            f'active risk execution router contains forbidden selector/semantic {forbidden!r}')

for marker in (
    'REQUIRED_SCHEMA_VERSION = 27',
    'PostgresActiveRiskMethodExecutionBindingStore',
    'PostgresRiskMethodSelectionPolicyActivationStore',
    'DefaultActiveRiskMethodResultMaterializer',
    'formula.materializer()',
    'derived.materializer()',
    'new DefaultActiveRiskMethodExecutionBindingMaterializer(',
    'policies,',
    'activations,',
    'nativeResults,',
    'bindings',
):
    require(marker in RUNTIME, f'active risk execution runtime missing {marker!r}')

for marker in (
    'activeRiskMethodExecutionRouter',
    'enableActiveRiskMethodExecutionApi',
    'ActiveRiskMethodExecutionHttpRouter.requiredRole(exchange, method)',
    'authorize(exchange, requiredRole)',
    'ACTIVE_RISK_METHOD_EXECUTION_PERSISTENCE_UNAVAILABLE',
    'ActiveRiskMethodExecutionApi.ApiProblem',
    'activeRiskMethodExecutionRuntime',
    'ActiveRiskMethodExecutionRuntimeFactory.fromEnvironment(System.getenv())',
    'rbvm_active_risk_method_execution_api_enabled',
):
    require(marker in SERVER, f'CsvPlatformServer missing active execution wiring {marker!r}')

for marker in (
    'executesExactFormulaAndReplaysBindingWithoutReexecution',
    'exposesExactDerivedResultLocation',
    'rejectsInvalidMissingWrongAndClearedIdentities',
    'executionStatus',
    'INSERTED',
    'REPLAYED',
):
    require(marker in API_TEST, f'active execution API self-test missing proof {marker!r}')

for marker in (
    'executesReplaysAndReadsExactBinding',
    'rejectsCurrentQueriesBodiesAndWrongMethods',
    'protectsV27CapabilityBehindAuthorization',
    'inserted.statusCode() == 201',
    'replay.statusCode() == 200',
    'fixture.results().calls == 1',
    'query.statusCode() == 400',
    'body.statusCode() == 400',
    'wrongMethod.statusCode() == 405',
    'current.statusCode() == 404',
    'collection.statusCode() == 404',
    'unauthenticatedExecution.statusCode() == 401',
    'viewerExecution.statusCode() == 403',
    'operatorExecution.statusCode() == 503',
    'viewerRead.statusCode() == 503',
):
    require(marker in HTTP_TEST, f'active execution HTTP self-test missing proof {marker!r}')

require('ActiveRiskMethodExecutionApiSelfTest.main(args);' in PLATFORM,
        'Active execution API self-test must run in PlatformSelfTest')
require('CsvActiveRiskMethodExecutionHttpSelfTest.main(args);' in PLATFORM,
        'Active execution HTTP self-test must run in PlatformSelfTest')

execute_path = '/api/v1/active-risk-method-executions/{activationRevision}/{activationEventSha256}/{inputSnapshotSha256}'
binding_path = '/api/v1/active-risk-method-execution-bindings/{bindingSha256}'
paths = SPEC.get('paths', {})
require(set(paths.keys()) == {execute_path, binding_path},
        'Active execution dedicated OpenAPI must expose exactly two paths')
require(set(paths[execute_path].keys()) == {'post'}, 'Execution OpenAPI path must be POST-only')
require(set(paths[binding_path].keys()) == {'get'}, 'Binding OpenAPI path must be GET-only')
post = paths[execute_path]['post']
get = paths[binding_path]['get']
require('requestBody' not in post and 'requestBody' not in get,
        'Active execution OpenAPI must not admit request bodies')
require(post.get('operationId') == 'executeActiveRiskMethodExactIdentity',
        'Execution OpenAPI operationId drifted')
require(get.get('operationId') == 'getActiveRiskMethodExecutionBindingBySha256',
        'Binding OpenAPI operationId drifted')
require([p.get('name') for p in post.get('parameters', [])] == [
    'activationRevision', 'activationEventSha256', 'inputSnapshotSha256'
], 'Execution OpenAPI must expose exactly the three explicit path identities')
require([p.get('name') for p in get.get('parameters', [])] == ['bindingSha256'],
        'Binding OpenAPI must expose only bindingSha256')
require(set(post.get('responses', {}).keys()) == {
    '200', '201', '400', '401', '403', '404', '409', '422', '500', '503'
}, 'Execution OpenAPI response set drifted')
require(set(get.get('responses', {}).keys()) == {
    '200', '400', '401', '403', '404', '503'
}, 'Binding OpenAPI response set drifted')

binding = SPEC['components']['schemas']['Binding']
required_binding = set(binding.get('required', []))
for field in (
    'bindingSha256', 'activationRevision', 'activationEventSha256',
    'policyRevision', 'policySha256', 'selectionRole', 'methodFamily',
    'methodId', 'methodVersion', 'methodSha256', 'inputSnapshotSha256',
    'resultFamily', 'resultSha256', 'canonicalPayloadFormat', 'canonicalPayloadBase64'
):
    require(field in required_binding, f'Execution binding OpenAPI must require {field!r}')
require(binding['properties']['selectionRole']['enum'] == ['PRIMARY'],
        'Execution binding selection role must remain PRIMARY only')
require(binding['properties']['methodFamily']['enum'] == ['RBVM_FORMULA', 'STANDARD_DERIVED'],
        'Execution binding method families drifted')

for target, label in ((COMBINED, 'combined'), (COMPOSED, 'composed')):
    require('/active-risk-method-executions/{activationRevision}/{activationEventSha256}/{inputSnapshotSha256}' in target,
            f'{label} OpenAPI missing exact execution path')
    require('/active-risk-method-execution-bindings/{bindingSha256}' in target,
            f'{label} OpenAPI missing exact binding path')
    require('active-risk-method-execution-v1.openapi.yaml' in target,
            f'{label} OpenAPI must reference dedicated execution contract')

for marker in (
    'RBVM_ACTIVE_RISK_METHOD_EXECUTION_API_V1',
    'POST /api/v1/active-risk-method-executions/{activationRevision}/{activationEventSha256}/{inputSnapshotSha256}',
    'GET /api/v1/active-risk-method-execution-bindings/{bindingSha256}',
    'OPERATOR',
    'VIEWER',
    'There is deliberately no execution route containing `current`',
    'does not re-execute the risk method',
    'query parameters and request bodies are rejected',
    'ETag',
    'Location',
    'Priority',
    'Treatment',
    'SLA',
):
    require(marker.lower() in DOC.lower(), f'active execution documentation missing {marker!r}')

require('verify-active-risk-method-execution-api.py' in VERIFY_SH,
        'Active execution API verifier must be wired into verify.sh')

print('Active Risk Method Execution API/HTTP/OpenAPI V1 checks: PASS')
