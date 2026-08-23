#!/usr/bin/env python3
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
API = (ROOT / "src/main/java/io/rbvm/csv/FormulaCatalogApi.java").read_text(encoding="utf-8")
FORMULA = (ROOT / "src/main/java/io/rbvm/decision/RbvmFormulaV1.java").read_text(encoding="utf-8")
ROUTER = (ROOT / "src/main/java/io/rbvm/csv/FormulaResultHttpRouter.java").read_text(encoding="utf-8")
API_TEST = (ROOT / "src/test/java/io/rbvm/csv/FormulaCatalogApiSelfTest.java").read_text(encoding="utf-8")
HTTP_TEST = (ROOT / "src/test/java/io/rbvm/csv/CsvFormulaCatalogHttpSelfTest.java").read_text(encoding="utf-8")
PLATFORM = (ROOT / "src/test/java/io/rbvm/csv/PlatformSelfTest.java").read_text(encoding="utf-8")
DOC = (ROOT / "docs/FORMULA_CATALOG_API_V1.md").read_text(encoding="utf-8")
OPENAPI = yaml.safe_load((ROOT / "api/formula-catalog-v1.openapi.yaml").read_text(encoding="utf-8"))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


for marker in (
    'RBVM_FORMULA_CATALOG_API_V1',
    'EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT',
    'RbvmFormulaV1.FORMULA_ID',
    'RbvmFormulaV1.FORMULA_VERSION',
    'RbvmFormulaV1.FORMULA_SHA256',
    'RbvmFormulaV1.OUTPUT_NAME',
    'RbvmDecisionInputSnapshot.V3_ID',
    '"RBVM_POLICY"',
    '"0.00"',
    '"100.00"',
    'DIMENSIONLESS_RELATIVE_RISK_INDEX_NOT_PRIORITY_SLA_TREATMENT_OR_PROBABILITY',
    'RbvmFormulaV1.ResultState.COMPUTED.name()',
    'RbvmFormulaV1.ResultState.NOT_APPLICABLE.name()',
    'RbvmFormulaV1.ResultState.NON_COMPUTABLE.name()',
):
    require(marker in API, f"Formula catalog API missing invariant {marker!r}")

for forbidden in (
    'defaultFormula',
    'preferredFormula',
    'latestFormula',
    'currentFormula',
    'priorityScore',
    'priorityTier',
    'slaDays',
    'treatmentDecision',
    'remediationDeadline',
):
    require(forbidden not in API, f"Formula catalog API contains forbidden construct {forbidden!r}")

require('88bf31f510089b4209b1ffcf1c15b39fef60548209875334f084888316e9028e' in FORMULA,
        'Accepted Formula V1 SHA source contract drifted')
require('private static final String CATALOG_PATH = "/api/v1/formulas";' in ROUTER,
        'Formula HTTP router must expose /api/v1/formulas')
for marker in (
    'CATALOG_PATH.equals(path)',
    'private final FormulaCatalogApi catalog = new FormulaCatalogApi();',
    'Formula catalog discovery does not accept query parameters',
    'send(exchange, catalog.listFormulas())',
    'return ApiRole.VIEWER;',
):
    require(marker in ROUTER, f"Formula HTTP router missing catalog invariant {marker!r}")

for marker in (
    'exposesExactFormulaIdentityWithoutSelectionPreference',
    'FormulaCatalogApi.SELECTION_SEMANTICS',
    'RbvmFormulaV1.FORMULA_SHA256',
    'RBVM_POLICY',
    'NOT_PRIORITY_SLA_TREATMENT_OR_PROBABILITY',
):
    require(marker in API_TEST, f"Formula catalog API self-test missing proof {marker!r}")

for marker in (
    'exposesFormulaIdentityWithoutDefaultSelection',
    'protectsDisabledCatalogBehindViewerAuthentication',
    '/api/v1/formulas',
    '?latest=true',
    'queryRejected.statusCode() == 400',
    'writeRejected.statusCode() == 405',
    'unauthenticated.statusCode() == 401',
    'viewer.statusCode() == 503',
    'FORMULA RESULT PERSISTENCE UNAVAILABLE',
):
    require(marker in HTTP_TEST, f"Formula catalog HTTP self-test missing proof {marker!r}")

require('FormulaCatalogApiSelfTest.main(args);' in PLATFORM,
        'Formula catalog API self-test must run in PlatformSelfTest')
require('CsvFormulaCatalogHttpSelfTest.main(args);' in PLATFORM,
        'Formula catalog HTTP self-test must run in PlatformSelfTest')

require(OPENAPI.get('openapi') == '3.0.3', 'Formula catalog OpenAPI must declare 3.0.3')
paths = OPENAPI.get('paths', {})
require(set(paths) == {'/api/v1/formulas'}, 'Formula catalog OpenAPI must publish one discovery path')
operation = paths['/api/v1/formulas']
require(set(operation) == {'get'}, 'Formula catalog route must be GET-only')
get = operation['get']
require(get.get('security') == [{'bearerAuth': []}], 'Formula catalog must require bearer auth')
require(set(get.get('responses', {})) == {'200', '401', '503'},
        'Formula catalog OpenAPI response set drifted')

schemas = OPENAPI['components']['schemas']
catalog = schemas['FormulaCatalogResponse']['properties']
require(catalog['selectionSemantics']['enum'] == ['EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT'],
        'Formula catalog must explicitly declare no default')
definition = schemas['FormulaDefinition']['properties']
require(definition['formulaId']['enum'] == ['RBVM_FORMULA_V1'],
        'Formula catalog formulaId drifted')
require(definition['formulaVersion']['enum'] == [1], 'Formula catalog version drifted')
require(definition['classification']['enum'] == ['RBVM_POLICY'],
        'Formula catalog must classify Formula V1 as RBVM policy')
require(definition['inputContractId']['enum'] == ['RBVM_DECISION_INPUT_SNAPSHOT_V3'],
        'Formula catalog input contract drifted')
require(definition['numericMinimum']['enum'] == ['0.00']
        and definition['numericMaximum']['enum'] == ['100.00'],
        'Formula catalog numeric range drifted')
require(set(definition['resultStates']['items']['enum'])
        == {'COMPUTED', 'NOT_APPLICABLE', 'NON_COMPUTABLE'},
        'Formula catalog terminal states drifted')
require(definition['outputSemantics']['enum'] == [
    'DIMENSIONLESS_RELATIVE_RISK_INDEX_NOT_PRIORITY_SLA_TREATMENT_OR_PROBABILITY'
], 'Formula catalog output semantics drifted')

for marker in (
    'GET /api/v1/formulas',
    'EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT',
    'RBVM_FORMULA_V1',
    'RBVM_POLICY',
    'RBVM_DECISION_INPUT_SNAPSHOT_V3',
    '0.00 .. 100.00',
    'NOT_APPLICABLE',
    'NON_COMPUTABLE',
    '`latest` or `current` Formula',
    'default, primary, or preferred Formula',
    'Priority',
    'Treatment',
    'SLA',
    'browser Formula presentation must consume this catalog',
):
    require(marker.lower() in DOC.lower(), f"Formula catalog documentation missing {marker!r}")

print('RBVM Formula Catalog API/HTTP/OpenAPI checks: PASS')
