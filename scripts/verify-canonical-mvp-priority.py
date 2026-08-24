#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
METHOD = "88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388"

migration = (ROOT / "db/migration/V29__canonical_mvp_priority_persistence.sql").read_text()
writer = (ROOT / "src/main/java/io/rbvm/postgres/PostgresCanonicalMvpPriorityStore.java").read_text()
http = (ROOT / "src/main/java/io/rbvm/csv/CanonicalMvpPriorityHttpHandler.java").read_text()
read_http = (ROOT / "src/main/java/io/rbvm/csv/CanonicalMvpPriorityReadHttpHandler.java").read_text()
main = (ROOT / "src/main/java/io/rbvm/csv/RbvmPlatformMain.java").read_text()
compile_sh = (ROOT / "scripts/compile.sh").read_text()
ui_transform = (ROOT / "scripts/integrate-canonical-mvp-priority-ui.py").read_text()

checks = {
    "V29 table": "CREATE TABLE rbvm.finding_mvp_priority_result" in migration,
    "frozen method SHA in DB": METHOD in migration,
    "append-only trigger": "BEFORE UPDATE OR DELETE ON rbvm.finding_mvp_priority_result" in migration,
    "relative semantics comment": "Relative Pareto front" in migration,
    "source SHA bound": "source_csv_sha256" in migration and "file_sha256" in writer,
    "source SHA equality enforced": "identity.fileSha256().equals(sourceCsvSha256)" in writer,
    "exact import row lineage": all(token in writer for token in (
        "rbvm.import_observation", "rbvm.observation o", "rbvm.exposure_observation", "rbvm.exposure e",
        "io.source_row_number")),
    "no fuzzy materializer keys": not any(token in writer for token in (
        "observed_name =", "cve_id =", "observed_product_name =", "filename")),
    "collapsed Finding conflict guarded": "Multiple exact source rows map to one Finding with different MVP-priority outputs" in writer,
    "exact method SHA row validation": "METHOD_SHA256.equals(row.methodSha256())" in writer,
    "priority artifact parsed server-side": "Rfc4180CsvReader" in http,
    "source and priority artifact SHA": "String sourceSha = sha256(source)" in http and "String prioritySha = sha256(priorityCsv)" in http,
    "read is explicit materialized result": "CANONICAL_MVP_PRIORITY_READ_HTTP_V1" in read_http,
    "artifact inputs not new evidence": "ARTIFACT_BOUND_ADMITTED_INPUTS_NOT_NEW_CANONICAL_EVIDENCE" in read_http,
    "organizational risk remains non-computable": "NON_COMPUTABLE" in http and "NON_COMPUTABLE" in read_http,
    "routes registered": main.count("/api/v1/canonical-mvp-priorities") >= 3,
    "fail-closed UI compile integration": "integrate-canonical-mvp-priority-ui.py" in compile_sh,
    "UI does not use observer": "MutationObserver" not in ui_transform,
    "UI performs no Pareto math": not any(token in ui_transform for token in ("dominance_relation", "nondominated", "pareto_relations", "CVSS*EPSS", "riskScore")),
    "UI uses server result": "/api/v1/canonical-mvp-priorities/findings/" in ui_transform,
    "UI exact canonical action": "Persist to canonical Findings" in ui_transform,
}

failed = [name for name, ok in checks.items() if not ok]
if failed:
    raise SystemExit("Canonical MVP priority verification failed: " + ", ".join(failed))

print("Canonical MVP priority semantic verification: PASS")
