#!/usr/bin/env python3
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ROUTER = (ROOT / "src/main/java/io/rbvm/csv/FormulaResultHttpRouter.java").read_text(encoding="utf-8")
API = (ROOT / "src/main/java/io/rbvm/csv/FormulaResultApi.java").read_text(encoding="utf-8")
REPLAY = (ROOT / "src/main/java/io/rbvm/postgres/FormulaResultReplayVerifier.java").read_text(encoding="utf-8")
SELF_TEST = (ROOT / "src/test/java/io/rbvm/csv/CsvFormulaResultMaterializationHttpSelfTest.java").read_text(encoding="utf-8")
PLATFORM = (ROOT / "src/test/java/io/rbvm/csv/PlatformSelfTest.java").read_text(encoding="utf-8")
DOC = (ROOT / "docs/FORMULA_RESULT_MATERIALIZATION_V1.md").read_text(encoding="utf-8")
OPENAPI_PATH = ROOT / "api/formula-result-materialization-v1.openapi.yaml"
OPENAPI = yaml.safe_load(OPENAPI_PATH.read_text(encoding="utf-8"))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


for marker in (
    '"/api/v1/formula-result-materializations"',
    'MATERIALIZATION_ITEM_PATH',
    'return ApiRole.OPERATOR;',
    '"POST"',
    'Formula materialization does not accept query parameters',
    'FORMULA_MATERIALIZATION_BODY_NOT_ALLOWED',
    'api.materializeByInputSnapshotSha256(materialization.group(1))',
    'return ApiRole.VIEWER;',
):
    require(marker in ROUTER, f'Formula materialization router missing invariant {marker!r}')

for forbidden in (
    'DecisionInputSnapshotBuilder',
    'current_',
    'priorityTier',
    'priorityScore',
    'slaDays',
    'treatmentDecision',
    'remediationDeadline',
):
    require(forbidden not in ROUTER,
            f'Formula materialization router contains forbidden construct {forbidden!r}')

for marker in (
    'RBVM_FORMULA_RESULT_MATERIALIZATION_API_V1',
    'materializeByInputSnapshotSha256(String inputSnapshotSha256)',
    'replayVerifier.materializeExactSnapshot(snapshotSha)',
    'DefaultFormulaResultMaterializer.SnapshotNotFoundException',
    'DECISION_INPUT_SNAPSHOT_NOT_FOUND',
    'FORMULA_MATERIALIZATION_REQUIRES_DECISION_INPUT_V3',
    'FORMULA_RESULT_CONFLICT',
    'FormulaResultInstallResult.Status.INSERTED ? 201 : 200',
    '"Location", "/api/v1/formula-results/" + explanationSha',
    'body.put("replayVerified", true)',
    'body.put("relativeRiskIndex", decimal(stored.relativeRiskIndex()))',
):
    require(marker in API, f'Formula materialization API missing invariant {marker!r}')

for forbidden in (
    'DecisionInputSnapshotBuilder',
    'latest(',
    'current_',
    'priorityTier',
    'priorityScore',
    'slaDays',
    'treatmentDecision',
    'remediationDeadline',
):
    require(forbidden not in API,
            f'Formula materialization API contains forbidden construct {forbidden!r}')

for marker in (
    'materializeExactSnapshot(String inputSnapshotSha256)',
    'new DefaultFormulaResultMaterializer(',
    'decisionInputs,',
    'evidenceResolver,',
    'formulaResults,',
    'this',
):
    require(marker in REPLAY, f'Formula replay runtime missing materializer bridge {marker!r}')
require('DecisionInputSnapshotBuilder' not in REPLAY,
        'Formula replay/materialization runtime must not rebuild Decision Inputs')

for marker in (
    'materializesExactSnapshotThenReplaysWithoutDuplicate',
    'rejectsInvalidRequestShapesAndMissingSnapshot',
    'requiresOperatorBeforeDisabledCapabilityLookup',
    'inserted.statusCode() == 201',
    'replayed.statusCode() == 200',
    'formulaStore.rowCount() == 1',
    'relativeRiskIndex\\\": null',
    'queryRejected.statusCode() == 400',
    'bodyRejected.statusCode() == 400',
    'wrongMethod.statusCode() == 405',
    'unauthenticated.statusCode() == 401',
    'viewer.statusCode() == 403',
    'operator.statusCode() == 503',
):
    require(marker in SELF_TEST, f'Formula materialization HTTP self-test missing proof {marker!r}')

require('CsvFormulaResultMaterializationHttpSelfTest.main(args);' in PLATFORM,
        'Formula materialization HTTP self-test must run in PlatformSelfTest')

path = '/api/v1/formula-result-materializations/{inputSnapshotSha256}'
require(path in OPENAPI.get('paths', {}), 'Materialization OpenAPI path is missing')
operation = OPENAPI['paths'][path]
require(set(operation.keys()) == {'post'}, 'Materialization OpenAPI path must be POST-only')
post = operation['post']
require(post.get('operationId') == 'materializeFormulaResultByInputSnapshotSha256',
        'Materialization OpenAPI operationId drifted')
require('requestBody' not in post, 'Materialization OpenAPI must not admit a request body')
parameters = post.get('parameters', [])
require(len(parameters) == 1, 'Materialization OpenAPI must expose exactly one selector')
parameter = parameters[0]
require(parameter.get('name') == 'inputSnapshotSha256'
        and parameter.get('in') == 'path'
        and parameter.get('required') is True,
        'Materialization OpenAPI selector must be the required path SHA')
require(set(post.get('responses', {}).keys()) == {
    '200', '201', '400', '401', '403', '404', '409', '422', '503'
}, 'Materialization OpenAPI response set drifted')

schema = OPENAPI['components']['schemas']['MaterializationResponse']
required = set(schema.get('required', []))
for field in (
    'contractId', 'materializationStatus', 'inputSnapshotSha256', 'resultId',
    'formulaId', 'formulaVersion', 'formulaSha256', 'resultState', 'reasonCodes',
    'relativeRiskIndex', 'explanationSha256', 'replayVerified', 'persistedAt'
):
    require(field in required, f'Materialization response must require {field!r}')
require(schema['properties']['contractId']['enum'] == ['RBVM_FORMULA_RESULT_MATERIALIZATION_API_V1'],
        'Materialization OpenAPI contract ID drifted')
require(schema['properties']['materializationStatus']['enum'] == ['INSERTED', 'REPLAYED'],
        'Materialization status must expose only INSERTED/REPLAYED')
require(schema['properties']['replayVerified']['enum'] == [True],
        'Successful materialization responses must be replay-verified')
require(schema['properties']['relativeRiskIndex'].get('nullable') is True,
        'Terminal materialization results must permit a null risk index')

for marker in (
    'RBVM_FORMULA_RESULT_MATERIALIZATION_API_V1',
    'POST /api/v1/formula-result-materializations/{inputSnapshotSha256}',
    '`OPERATOR` permission is required',
    'query parameters are rejected',
    'request bodies are rejected',
    'HTTP `201`',
    'HTTP `200`',
    '`Location`',
    '`ETag`',
    'replayVerified: true',
    'Priority',
    'Treatment',
    'SLA',
):
    require(marker.lower() in DOC.lower(),
            f'Formula materialization HTTP documentation missing {marker!r}')

print('RBVM Formula Result Materialization HTTP/OpenAPI checks: PASS')
