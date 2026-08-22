#!/usr/bin/env python3
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ROUTER = (ROOT / "src/main/java/io/rbvm/csv/DerivedRiskResultHttpRouter.java").read_text(encoding="utf-8")
SERVER = (ROOT / "src/main/java/io/rbvm/csv/CsvPlatformServer.java").read_text(encoding="utf-8")
SELF_TEST = (ROOT / "src/test/java/io/rbvm/csv/CsvDerivedRiskResultHttpSelfTest.java").read_text(encoding="utf-8")
PLATFORM = (ROOT / "src/test/java/io/rbvm/csv/PlatformSelfTest.java").read_text(encoding="utf-8")
DOC = (ROOT / "docs/DERIVED_RISK_RESULT_HTTP_V1.md").read_text(encoding="utf-8")
READ_API = yaml.safe_load((ROOT / "api/derived-risk-result-v1.openapi.yaml").read_text(encoding="utf-8"))
MATERIALIZE_API = yaml.safe_load(
    (ROOT / "api/derived-risk-result-materialization-v1.openapi.yaml").read_text(encoding="utf-8")
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


for marker in (
    '"/api/v1/derived-risk-methodologies"',
    '"/api/v1/derived-risk-results"',
    '"/api/v1/derived-risk-result-materializations"',
    'MATERIALIZATION_ITEM_PATH',
    'return ApiRole.OPERATOR;',
    'return ApiRole.VIEWER;',
    'Set.of(',
    '"inputSnapshotSha256"',
    '"methodologyId"',
    '"methodologySha256"',
    'api.listMethodologies()',
    'api.getByResultSha256(item.group(1))',
    'api.getByInputSnapshotAndMethodology(',
    'api.materialize(',
    'DERIVED_RISK_MATERIALIZATION_BODY_NOT_ALLOWED',
    'Duplicate derived risk result query parameter',
):
    require(marker in ROUTER, f"Derived risk HTTP router missing invariant {marker!r}")

for forbidden in (
    'DecisionInputSnapshotBuilder',
    'preferredMethodology',
    'defaultMethodology',
    'priorityTier',
    'priorityScore',
    'slaDays',
    'treatmentDecision',
    'remediationDeadline',
):
    require(forbidden not in ROUTER,
            f"Derived risk HTTP router contains forbidden construct {forbidden!r}")

for marker in (
    'private Optional<DerivedRiskResultHttpRouter> derivedRiskResultRouter = Optional.empty();',
    'public void enableDerivedRiskResultApi(DerivedRiskResultApi api)',
    'if (DerivedRiskResultHttpRouter.inNamespace(path))',
    'DERIVED_RISK_RESULT_PERSISTENCE_UNAVAILABLE',
    'PostgreSQL schema version 24 or newer',
    '"derivedRiskResults", Map.of(',
    '"materializationEnabled", derivedRiskResultRouter.isPresent()',
    'rbvm_derived_risk_result_api_enabled',
    'DerivedRiskResultRuntimeFactory.fromEnvironment(System.getenv())',
    'application.enableDerivedRiskResultApi(',
    'new DerivedRiskResultApi(',
):
    require(marker in SERVER, f"CsvPlatformServer missing derived risk transport marker {marker!r}")

route_start = SERVER.index('if (DerivedRiskResultHttpRouter.inNamespace(path))')
route_end = SERVER.index('if ("/api/v1/cases".equals(path))', route_start)
route_block = SERVER[route_start:route_end]
required_role = route_block.index('DerivedRiskResultHttpRouter.requiredRole(exchange, method)')
authorize = route_block.index('authorize(exchange, requiredRole)')
capability = route_block.index('derivedRiskResultRouter.orElseThrow')
require(required_role < authorize < capability,
        'Derived risk route must authorize before V24 capability lookup')

for marker in (
    'exposesCatalogExactReadsAndExplicitMaterialization',
    'rejectsInvalidRequestShapesAndAliases',
    'protectsDisabledCapabilityBehindViewerAndOperatorAuthorization',
    'EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT',
    'fixture.store().size() == 2',
    'owasp_derived_rbvm_v1',
    'latest=true',
    'inserted.statusCode() == 201',
    'replayed.statusCode() == 200',
    'viewerWrite.statusCode() == 403',
    'operatorWrite.statusCode() == 503',
    'rbvm_derived_risk_result_api_enabled 1',
    'rbvm_derived_risk_result_api_enabled 0',
):
    require(marker in SELF_TEST, f"Derived risk HTTP self-test missing proof {marker!r}")

require('CsvDerivedRiskResultHttpSelfTest.main(args);' in PLATFORM,
        'Derived risk HTTP self-test must run in PlatformSelfTest')

require(READ_API.get('openapi') == '3.0.3', 'Derived risk read OpenAPI must declare 3.0.3')
read_paths = READ_API.get('paths', {})
expected_read_paths = {
    '/api/v1/derived-risk-methodologies',
    '/api/v1/derived-risk-results',
    '/api/v1/derived-risk-results/{resultSha256}',
}
require(set(read_paths) == expected_read_paths,
        'Derived risk read OpenAPI must publish only exact catalog/result paths')
for path, item in read_paths.items():
    require(set(item) == {'get'}, f'{path} must be GET-only')
    require(item['get'].get('security', READ_API.get('security')) == [{'bearerAuth': []}],
            f'{path} must require bearer authentication')
    require('200' in item['get'].get('responses', {}), f'{path} must document 200')
    require('503' in item['get'].get('responses', {}), f'{path} must document capability 503')

catalog_schema = READ_API['components']['schemas']['MethodologyCatalogResponse']['properties']
require(catalog_schema['selectionSemantics']['enum'] == ['EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT'],
        'Methodology catalog OpenAPI must explicitly declare no default')

collection_params = {
    parameter.get('name'): parameter
    for parameter in read_paths['/api/v1/derived-risk-results']['get'].get('parameters', [])
}
require(set(collection_params) == {
    'inputSnapshotSha256', 'methodologyId', 'methodologySha256'
}, 'Derived risk collection lookup must expose exactly three immutable selectors')
require(all(parameter.get('required') is True for parameter in collection_params.values()),
        'All derived risk collection selectors must be required')
require('latest' not in collection_params and 'current' not in collection_params,
        'Derived risk OpenAPI must not publish latest/current selection')

stored = READ_API['components']['schemas']['StoredDerivedRiskResult']['properties']
require(stored['numericScore'].get('type') == 'string'
        and stored['numericScore'].get('nullable') is True,
        'Derived risk numericScore must remain a nullable exact decimal string')
require(set(stored['resultState']['enum']) == {'COMPUTED', 'NOT_APPLICABLE', 'NON_COMPUTABLE'},
        'Derived risk OpenAPI must preserve terminal result states')
canonical = READ_API['components']['schemas']['CanonicalDerivedRiskResult']['properties']
require(canonical['replayVerified']['enum'] == [True],
        'Successful derived risk reads must be replay-verified')

require(MATERIALIZE_API.get('openapi') == '3.0.3',
        'Derived risk materialization OpenAPI must declare 3.0.3')
materialize_path = (
    '/api/v1/derived-risk-result-materializations/'
    '{inputSnapshotSha256}/{methodologyId}/{methodologySha256}'
)
require(set(MATERIALIZE_API.get('paths', {})) == {materialize_path},
        'Derived risk materialization OpenAPI must publish one explicit command path')
operation = MATERIALIZE_API['paths'][materialize_path]
require(set(operation) == {'post'}, 'Derived risk materialization path must be POST-only')
post = operation['post']
require(post.get('operationId') == 'materializeDerivedRiskResult',
        'Derived risk materialization operationId drifted')
require('requestBody' not in post, 'Derived risk materialization must not admit a request body')
parameters = post.get('parameters', [])
require([parameter.get('name') for parameter in parameters] == [
    'inputSnapshotSha256', 'methodologyId', 'methodologySha256'
], 'Materialization path must expose exactly the three explicit immutable selectors')
require(all(parameter.get('in') == 'path' and parameter.get('required') is True
            for parameter in parameters),
        'All materialization selectors must be required path parameters')
require(set(post.get('responses', {})) == {
    '200', '201', '400', '401', '403', '404', '409', '422', '503'
}, 'Derived risk materialization response set drifted')
materialized = MATERIALIZE_API['components']['schemas']['MaterializationResponse']['properties']
require(materialized['materializationStatus']['enum'] == ['INSERTED', 'REPLAYED'],
        'Materialization status must expose only INSERTED/REPLAYED')
require(materialized['replayVerified']['enum'] == [True],
        'Successful derived risk materialization must be replay-verified')
require(materialized['numericScore'].get('nullable') is True,
        'Terminal materialization results must permit null numeric score')

for marker in (
    'GET /api/v1/derived-risk-methodologies',
    'GET /api/v1/derived-risk-results/{resultSha256}',
    'inputSnapshotSha256={sha256}&methodologyId={canonicalId}&methodologySha256={sha256}',
    'POST /api/v1/derived-risk-result-materializations/{inputSnapshotSha256}/{methodologyId}/{methodologySha256}',
    'EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT',
    'authorization is resolved before runtime-capability lookup',
    'schema V24 or newer',
    'There is no `latest`, `current`',
    'methodology-native output semantics',
    'primary/preferred/default methodology',
    'average',
    'Priority',
    'Treatment',
    'SLA',
):
    require(marker.lower() in DOC.lower(),
            f"Derived risk HTTP documentation missing boundary {marker!r}")

print('RBVM Derived Risk Result HTTP/runtime/OpenAPI checks: PASS')
