#!/usr/bin/env python3
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ROUTER = (ROOT / "src/main/java/io/rbvm/csv/FormulaResultHttpRouter.java").read_text(encoding="utf-8")
RUNTIME = (ROOT / "src/main/java/io/rbvm/postgres/FormulaResultRuntimeFactory.java").read_text(encoding="utf-8")
SERVER = (ROOT / "src/main/java/io/rbvm/csv/CsvPlatformServer.java").read_text(encoding="utf-8")
SELF_TEST = (ROOT / "src/test/java/io/rbvm/csv/CsvFormulaResultHttpSelfTest.java").read_text(encoding="utf-8")
PLATFORM = (ROOT / "src/test/java/io/rbvm/csv/PlatformSelfTest.java").read_text(encoding="utf-8")
DOC = (ROOT / "docs/FORMULA_RESULT_API_V1.md").read_text(encoding="utf-8")
OPENAPI_PATH = ROOT / "api/formula-result-v1.openapi.yaml"
OPENAPI = yaml.safe_load(OPENAPI_PATH.read_text(encoding="utf-8"))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


for marker in (
    '"/api/v1/formula-results"',
    'ApiRole.VIEWER',
    'if (!"GET".equals(method))',
    'Set.of("inputSnapshotSha256", "formulaSha256")',
    'api.getByInputSnapshotAndFormula(snapshotSha, formulaSha)',
    'api.getByExplanationSha256(item.group(1))',
    'Exact explanation lookup does not accept query parameters',
    'Duplicate Formula result query parameter',
):
    require(marker in ROUTER, f"Formula Result HTTP router missing invariant {marker!r}")

for forbidden in (
    'POST(',
    'priorityTier',
    'priorityScore',
    'slaDays',
    'treatmentDecision',
    'remediationDeadline',
    'DecisionInputSnapshotBuilder',
):
    require(forbidden not in ROUTER,
            f"Formula Result HTTP router contains forbidden construct {forbidden!r}")

for marker in (
    'private static final int REQUIRED_SCHEMA_VERSION = 23;',
    'PostgresFormulaResultStore',
    'PostgresDecisionInputSnapshotStore',
    'PostgresDecisionInputEvidenceResolver',
    'FormulaResultReplayVerifier',
    'if (installedVersion < REQUIRED_SCHEMA_VERSION)',
):
    require(marker in RUNTIME, f"Formula Result runtime factory missing invariant {marker!r}")

for forbidden in (
    'DecisionInputSnapshotBuilder',
    'latest(',
    'priorityTier',
    'slaDays',
    'treatmentDecision',
):
    require(forbidden not in RUNTIME,
            f"Formula Result runtime factory contains forbidden construct {forbidden!r}")

server_markers = (
    'private Optional<FormulaResultHttpRouter> formulaResultRouter = Optional.empty();',
    'public void enableFormulaResultApi(FormulaResultApi api)',
    'if (FormulaResultHttpRouter.inNamespace(path))',
    'FORMULA_RESULT_PERSISTENCE_UNAVAILABLE',
    '"formulaResults", Map.of(',
    '"replayVerified", formulaResultRouter.isPresent()',
    'rbvm_formula_result_api_enabled',
    'FormulaResultRuntimeFactory.fromEnvironment(System.getenv())',
    'application.enableFormulaResultApi(',
)
for marker in server_markers:
    require(marker in SERVER, f"CsvPlatformServer missing Formula Result transport marker {marker!r}")

route_start = SERVER.index('if (FormulaResultHttpRouter.inNamespace(path))')
route_end = SERVER.index('if ("/api/v1/cases".equals(path))', route_start)
route_block = SERVER[route_start:route_end]
required_role = route_block.index('FormulaResultHttpRouter.requiredRole(exchange, method)')
authorize = route_block.index('authorize(exchange, requiredRole)')
capability = route_block.index('formulaResultRouter.orElseThrow')
require(required_role < authorize < capability,
        'Formula Result route must resolve RBAC and authorize before capability lookup')

for marker in (
    'exposesExactReplayVerifiedReadsOnly',
    'reportsDisabledCapabilityWithoutV23',
    'protectsDisabledCapabilityBehindViewerAuthentication',
    '"&latest=true"',
    'writeRejected.statusCode() == 405',
    'unauthenticated.statusCode() == 401',
    'viewer.statusCode() == 503',
    'rbvm_formula_result_api_enabled 1',
    'rbvm_formula_result_api_enabled 0',
):
    require(marker in SELF_TEST, f"Formula Result HTTP self-test missing proof {marker!r}")

require('CsvFormulaResultHttpSelfTest.main(args);' in PLATFORM,
        'Formula Result HTTP self-test must run in PlatformSelfTest')

require(OPENAPI.get('openapi') == '3.0.3', 'Formula Result OpenAPI must declare 3.0.3')
paths = OPENAPI.get('paths', {})
expected_paths = {
    '/api/v1/formula-results/{explanationSha256}',
    '/api/v1/formula-results',
}
require(set(paths) == expected_paths,
        'Formula Result OpenAPI must publish only the two exact read paths')
for path, item in paths.items():
    require(set(item) == {'get'}, f'{path} must be GET-only')
    operation = item['get']
    require(operation.get('security') == [{'bearerAuth': []}],
            f'{path} must require bearer authentication in OpenAPI')
    require('200' in operation.get('responses', {}), f'{path} must document 200')
    require('503' in operation.get('responses', {}), f'{path} must document capability 503')

collection_params = {
    parameter.get('name'): parameter
    for parameter in paths['/api/v1/formula-results']['get'].get('parameters', [])
}
require(set(collection_params) == {'inputSnapshotSha256', 'formulaSha256'},
        'Collection lookup must expose exactly the two immutable SHA identities')
require(all(parameter.get('required') is True for parameter in collection_params.values()),
        'Both Formula Result collection identities must be required')
require('latest' not in collection_params, 'Formula Result OpenAPI must not publish latest selection')

item_params = paths['/api/v1/formula-results/{explanationSha256}']['get'].get('parameters', [])
require(len(item_params) == 1 and item_params[0].get('name') == 'explanationSha256'
        and item_params[0].get('required') is True,
        'Item lookup must require only canonical explanation SHA')

schemas = OPENAPI.get('components', {}).get('schemas', {})
result_state = schemas.get('FormulaResult', {}).get('properties', {}).get('resultState', {})
require(set(result_state.get('enum', [])) == {'COMPUTED', 'NOT_APPLICABLE', 'NON_COMPUTABLE'},
        'Formula Result OpenAPI must preserve terminal result states')
relative_risk = schemas.get('FormulaResult', {}).get('properties', {}).get('relativeRiskIndex', {})
require(relative_risk.get('type') == 'string' and relative_risk.get('nullable') is True,
        'Relative Risk Index must remain an exact nullable decimal string')
replay_verified = schemas.get('FormulaExplanation', {}).get('properties', {}).get('replayVerified', {})
require(replay_verified.get('enum') == [True],
        'Successful Formula explanation responses must be replay-verified')

for marker in (
    'GET /api/v1/formula-results/{explanationSha256}',
    'GET /api/v1/formula-results?inputSnapshotSha256={sha256}&formulaSha256={sha256}',
    'authorization is resolved before runtime-capability lookup',
    'PostgreSQL projection is active and schema V23 or newer',
    'there is no `latest`',
    'Frontend System V2 does not yet present Formula results',
    'Priority',
    'Treatment',
    'SLA',
):
    require(marker.lower() in DOC.lower(),
            f"Formula Result API documentation missing transport boundary {marker!r}")

print('RBVM Formula Result HTTP/runtime/OpenAPI structural checks: PASS')
