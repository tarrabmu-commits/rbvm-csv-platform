#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = (ROOT / "src/main/java/io/rbvm/csv/FormulaResultApi.java").read_text(encoding="utf-8")
REPLAY = (ROOT / "src/main/java/io/rbvm/postgres/FormulaResultReplayVerifier.java").read_text(encoding="utf-8")
SELF_TEST = (ROOT / "src/test/java/io/rbvm/csv/FormulaResultApiSelfTest.java").read_text(encoding="utf-8")
PLATFORM = (ROOT / "src/test/java/io/rbvm/csv/PlatformSelfTest.java").read_text(encoding="utf-8")
DOC = (ROOT / "docs/FORMULA_RESULT_API_V1.md").read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


for marker in (
    'RBVM_FORMULA_RESULT_API_V1',
    'getByExplanationSha256',
    'getByInputSnapshotAndFormula',
    'findByExplanationSha256',
    'findBySnapshotAndFormula',
    'replayVerifier.replay(stored)',
    'canonicalPayloadBase64',
    'replayVerified',
    'evidenceReferences',
    'nativeEvidenceKind',
    'bindingKind',
    'bindingSha256',
    'relativeRiskIndex',
    'value.toPlainString()',
    'formula-result-',
    'FORMULA_RESULT_NOT_FOUND',
    'INVALID_FORMULA_RESULT_IDENTITY',
):
    require(marker in API, f"Formula Result API V1 missing invariant {marker!r}")

for forbidden in (
    'priorityTier',
    'priorityScore',
    'slaDays',
    'treatmentDecision',
    'remediationDeadline',
    'latest(',
    'current_',
    'DecisionInputSnapshotBuilder',
):
    require(forbidden not in API,
            f"Formula Result API must not contain downstream/current-selection construct {forbidden!r}")

for marker in (
    'public RbvmFormulaV1Explanation replay(StoredFormulaResult stored)',
    '.findBySha256(stored.inputSnapshotSha256())',
    'evidenceResolver.resolve(snapshot)',
    'RbvmFormulaV1.evaluate(resolved)',
    'Arrays.equals(stored.explanationPayload(), replayed.canonicalPayload())',
):
    require(marker in REPLAY, f"Replay-verified API boundary missing {marker!r}")

for marker in (
    'returnsReplayVerifiedExactResultByExplanationIdentity',
    'returnsReplayVerifiedExactResultBySnapshotAndFormulaIdentity',
    'returnsComputedDecimalsAndExactBindingProvenance',
    'rejectsInvalidAndMissingIdentities',
    'failsClosedWhenHistoricalReplayDoesNotMatchStorage',
    'canonicalPayloadBase64',
    'relativeRiskIndex") == null',
    'relativeRiskIndex").equals("45.00")',
    'weightedContribution").equals("0.13")',
    'FINDING_REACHABILITY_SCOPE_LINK_EVENT',
    'bindingSha256',
    'bindingSource',
    'recordedAt',
):
    require(marker in SELF_TEST, f"Formula Result API self-test missing {marker!r}")

require('FormulaResultApiSelfTest.main(args);' in PLATFORM,
        'Formula Result API self-test must run in PlatformSelfTest')

for marker in (
    'RBVM_FORMULA_RESULT_API_V1',
    'exact immutable identity',
    'replay-verified',
    'no latest',
    'HTTP and runtime transport',
    'GET /api/v1/formula-results/{explanationSha256}',
    'Priority',
    'Treatment',
    'SLA',
):
    require(marker.lower() in DOC.lower(), f"Formula Result API documentation missing {marker!r}")

print('RBVM Formula Result API V1 structural checks: PASS')
