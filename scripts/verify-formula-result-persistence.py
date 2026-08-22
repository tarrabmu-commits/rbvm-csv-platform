#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = (ROOT / "db/migration/V23__formula_result_persistence.sql").read_text(encoding="utf-8")
STORE = (ROOT / "src/main/java/io/rbvm/postgres/PostgresFormulaResultStore.java").read_text(encoding="utf-8")
MODEL = (ROOT / "src/main/java/io/rbvm/postgres/StoredFormulaResult.java").read_text(encoding="utf-8")
REPLAY = (ROOT / "src/main/java/io/rbvm/postgres/FormulaResultReplayVerifier.java").read_text(encoding="utf-8")
MIGRATOR = (ROOT / "src/main/java/io/rbvm/postgres/PostgresMigrator.java").read_text(encoding="utf-8")
ROLE = (ROOT / "db/security/runtime-role.sql").read_text(encoding="utf-8")
SELF_TEST = (ROOT / "src/test/java/io/rbvm/postgres/FormulaResultReplayVerifierSelfTest.java").read_text(encoding="utf-8")
PLATFORM = (ROOT / "src/test/java/io/rbvm/csv/PlatformSelfTest.java").read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


normalized = " ".join(MIGRATION.split()).upper()
require(normalized.startswith("BEGIN;") and normalized.endswith("COMMIT;"),
        "V23 migration must be transaction-wrapped")
for marker in (
    "CREATE TABLE RBVM.FORMULA_RESULT",
    "FORMULA_ID TEXT NOT NULL CHECK (FORMULA_ID = 'RBVM_FORMULA_V1')",
    "FORMULA_VERSION INTEGER NOT NULL CHECK (FORMULA_VERSION = 1)",
    "88BF31F510089B4209B1FFCF1C15B39FEF60548209875334F084888316E9028E",
    "RESULT_STATE IN ('COMPUTED', 'NOT_APPLICABLE', 'NON_COMPUTABLE')",
    "EXPLANATION_PAYLOAD_FORMAT = 'RBVM_FORMULA_EXPLANATION_CANONICAL_BINARY_V1'",
    "UNIQUE ( TENANT_ID, INPUT_SNAPSHOT_SHA256, FORMULA_ID, FORMULA_VERSION, FORMULA_SHA256 )",
    "REFERENCES RBVM.DECISION_INPUT_SNAPSHOT",
    "RELATIVE_RISK_INDEX IS NULL",
    "CARDINALITY(REASON_CODES) = 0",
    "CARDINALITY(REASON_CODES) >= 1",
):
    require(marker in normalized, f"V23 Formula persistence missing invariant {marker!r}")

for forbidden in (
    "PRIORITY_TIER",
    "SLA_DAYS",
    "TREATMENT_DECISION",
    "REMEDIATION_DEADLINE",
):
    require(forbidden not in normalized,
            f"V23 Formula persistence must not derive downstream policy field {forbidden}")

for marker in (
    "TRANSACTION_SERIALIZABLE",
    "pg_advisory_xact_lock",
    "requireExactDecisionInput",
    "RbvmDecisionInputSnapshot.V3_ID",
    "explanation.canonicalSha256()",
    "explanation.canonicalPayload()",
    "RESULT_CONFLICT",
    "deterministicResultId",
):
    require(marker in STORE, f"Postgres Formula store missing invariant {marker!r}")

require("MessageDigest.getInstance(\"SHA-256\")" in MODEL,
        "Stored Formula result must validate explanation SHA-256 integrity")
require("return explanationPayload.clone();" in MODEL,
        "Stored Formula result must protect canonical payload bytes")
require("relativeRiskIndex must be 0.00..100.00 with scale 2" in MODEL,
        "Stored Formula result must preserve Formula numeric shape")
require("must not carry a numeric risk index" in MODEL,
        "terminal Formula results must remain non-numeric")

for marker in (
    ".findBySha256(stored.inputSnapshotSha256())",
    "evidenceResolver.resolve(snapshot)",
    "RbvmFormulaV1.evaluate(resolved)",
    "RbvmFormulaV1Explanation.from",
    "Arrays.equals(stored.explanationPayload(), replayed.canonicalPayload())",
    "historical replay verification",
):
    require(marker in REPLAY, f"Formula replay verifier missing invariant {marker!r}")
for forbidden in (
    "DecisionInputSnapshotBuilder",
    "current_",
    "build(",
):
    require(forbidden not in REPLAY,
            f"Formula replay verifier must not reselect current evidence via {forbidden!r}")

require('new Migration(23, "V23__formula_result_persistence.sql")' in MIGRATOR,
        "PostgresMigrator must register V23")
require("rbvm.formula_result" in ROLE,
        "runtime role must receive Formula-result relation access")
require("REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.formula_result FROM rbvm_runtime;" in ROLE,
        "Formula-result runtime relation must be append-only")

for marker in (
    "verifiesExactHistoricalReplay",
    "rejectsStoredSemanticDriftEvenWhenExplanationBytesAreIntact",
    "rejectsMissingDecisionInputSnapshot",
):
    require(marker in SELF_TEST, f"Formula replay self-test missing {marker}")
require("FormulaResultReplayVerifierSelfTest.main(args);" in PLATFORM,
        "Formula replay self-test must run in PlatformSelfTest")

print("RBVM Formula V1 persistence/replay structural checks: PASS")
