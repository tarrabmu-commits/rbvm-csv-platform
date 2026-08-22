#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BOUNDARY = (ROOT / "src/main/java/io/rbvm/postgres/FormulaResultMaterializer.java").read_text(encoding="utf-8")
RESULT = (ROOT / "src/main/java/io/rbvm/postgres/FormulaResultMaterializationResult.java").read_text(encoding="utf-8")
DEFAULT = (ROOT / "src/main/java/io/rbvm/postgres/DefaultFormulaResultMaterializer.java").read_text(encoding="utf-8")
RUNTIME = (ROOT / "src/main/java/io/rbvm/postgres/FormulaResultRuntimeFactory.java").read_text(encoding="utf-8")
SELF_TEST = (ROOT / "src/test/java/io/rbvm/postgres/DefaultFormulaResultMaterializerSelfTest.java").read_text(encoding="utf-8")
LIVE_TEST = (ROOT / "src/test/java/io/rbvm/postgres/PostgresV23FormulaResultLiveSelfTest.java").read_text(encoding="utf-8")
PLATFORM = (ROOT / "src/test/java/io/rbvm/csv/PlatformSelfTest.java").read_text(encoding="utf-8")
DOC = (ROOT / "docs/FORMULA_RESULT_MATERIALIZATION_V1.md").read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


require('materialize(String inputSnapshotSha256)' in BOUNDARY,
        'Formula materialization boundary must accept exact snapshot SHA only')
for forbidden in ('findingId', 'methodologyRevision', 'evaluatedAt', 'DecisionInputSnapshotBuilder'):
    require(forbidden not in BOUNDARY,
            f'Formula materialization boundary must not accept selector {forbidden!r}')

for marker in (
    'snapshots.findBySha256(snapshotSha)',
    'if (!snapshot.isV3())',
    'snapshot.snapshotSha256().equals(snapshotSha)',
    'evidenceResolver.resolve(snapshot)',
    'RbvmFormulaV1.evaluate(resolved)',
    'RbvmFormulaV1Explanation.from(',
    'results.install(explanation)',
    'FormulaResultInstallResult.Status.RESULT_CONFLICT',
    '.findByExplanationSha256(explanation.canonicalSha256())',
    'replayVerifier.replay(stored)',
):
    require(marker in DEFAULT, f'Exact Formula materializer missing invariant {marker!r}')

for forbidden in (
    'DecisionInputSnapshotBuilder',
    'materializer.build',
    'latest(',
    'current_',
    'priorityTier',
    'priorityScore',
    'slaDays',
    'treatmentDecision',
    'remediationDeadline',
):
    require(forbidden not in DEFAULT,
            f'Formula materializer contains forbidden current/downstream construct {forbidden!r}')

for marker in (
    'installResult.installedOrReplayed()',
    'explanation.canonicalSha256().equals(storedResult.explanationSha256())',
    'explanation.inputSnapshotSha256().equals(storedResult.inputSnapshotSha256())',
):
    require(marker in RESULT, f'Materialization result identity guard missing {marker!r}')

for marker in (
    'private static final int REQUIRED_SCHEMA_VERSION = 23;',
    'PostgresFormulaResultStore',
    'PostgresDecisionInputSnapshotStore',
    'PostgresDecisionInputEvidenceResolver',
    'FormulaResultReplayVerifier',
    'DefaultFormulaResultMaterializer',
    'FormulaResultMaterializer materializer',
):
    require(marker in RUNTIME, f'Formula runtime missing materialization wiring {marker!r}')
require('DecisionInputSnapshotBuilder' not in RUNTIME,
        'Formula materialization runtime must not rebuild Decision Inputs')

for marker in (
    'materializesOnlyTheExactPersistedV3SnapshotAndReplays',
    'rejectsMalformedMissingAndNonV3Snapshots',
    'failsClosedOnFormulaResultConflict',
    'failsClosedWhenPersistedResultCannotReplay',
    'FormulaResultInstallResult.Status.INSERTED',
    'FormulaResultInstallResult.Status.REPLAYED',
    'finalRiskResult() == null',
):
    require(marker in SELF_TEST, f'Materializer self-test missing proof {marker!r}')

require('DefaultFormulaResultMaterializerSelfTest.main(args);' in PLATFORM,
        'Formula materializer self-test must run in PlatformSelfTest')

for marker in (
    'DefaultFormulaResultMaterializer materializer',
    'materializer.materialize(snapshotSha)',
    'FormulaResultInstallResult.Status.INSERTED',
    'FormulaResultInstallResult.Status.REPLAYED',
    'formulaRowCount(runtimeConnections) == 1',
    'materialization=PASS',
):
    require(marker in LIVE_TEST, f'V23 live test missing production materialization proof {marker!r}')

for marker in (
    'FORMULA_RESULT_MATERIALIZATION_V1',
    'RBVM_FORMULA_RESULT_MATERIALIZATION_API_V1',
    'exact already-persisted `RBVM_DECISION_INPUT_SNAPSHOT_V3` identity',
    'inputSnapshotSha256',
    'There is no call to `DecisionInputSnapshotBuilder`',
    'INSERTED',
    'REPLAYED',
    'RESULT_CONFLICT',
    'Operator HTTP transport',
    'Priority',
    'Treatment',
    'SLA',
):
    require(marker.lower() in DOC.lower(),
            f'Formula materialization documentation missing {marker!r}')

print('RBVM Formula Result Materialization V1 structural checks: PASS')
