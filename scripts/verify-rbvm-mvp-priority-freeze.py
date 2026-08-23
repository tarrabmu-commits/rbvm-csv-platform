#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "docs/fixtures/RBVM_MVP_PRIORITY_POLICY_V1_FREEZE.json"
FREEZE_DOC = ROOT / "docs/RBVM_MVP_PRIORITY_POLICY_V1_FREEZE.md"
POLICY_DOC = ROOT / "docs/RBVM_MVP_PRIORITY_POLICY_V1.md"
POLICY_SCRIPT = ROOT / "scripts/rank-rbvm-mvp-priority.py"
GOLDEN = ROOT / "testdata/rbvm-mvp-priority-golden.csv"
LIVE = ROOT / "scripts/run-csv-v2-live-benchmark.sh"
HTTP = ROOT / "src/main/java/io/rbvm/csv/CsvFirstMvpPriorityHttpHandler.java"
RUN_VISUALS = ROOT / "src/main/resources/web/csv-run-visuals.js"

FREEZE_ID = "RBVM_MVP_PRIORITY_POLICY_V1_FREEZE_V1"
METHOD_ID = "RBVM_MVP_PRIORITY_POLICY_V1"
METHOD_SHA = "88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388"
GOLDEN_SHA = "7a2fc323ce1e619386f20023b4ec84b7331241890a95691db7a577dbb0f50853"
REPORT_CONTRACT = "RBVM_MVP_PRIORITY_REPORT_V1"
EXPLAINABILITY_CONTRACT = "RBVM_MVP_PRIORITY_EXPLAINABILITY_V1"
HTTP_CONTRACT = "CSV_FIRST_MVP_PRIORITY_HTTP_V1"
LIVE_CONTRACT = "CSV_V2_LIVE_BENCHMARK_V4"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fail(message: str) -> None:
    raise AssertionError(message)


if not MANIFEST_PATH.is_file():
    fail("MVP methodology freeze manifest is missing")
manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

if manifest.get("freezeContractId") != FREEZE_ID:
    fail("freeze contract identity drift")
if manifest.get("freezeVersion") != 1 or manifest.get("status") != "FROZEN_FOR_MVP":
    fail("freeze status/version drift")
if manifest.get("frozenOn") != "2026-08-24":
    fail("freeze date drift")
if manifest.get("classification") != "RBVM_POLICY":
    fail("freeze classification drift")
if manifest.get("methodSha256") != METHOD_SHA:
    fail("frozen method SHA metadata drift")

# Load the policy module without invoking its CLI entry point and bind the
# freeze directly to the canonical representation used to calculate the SHA.
policy = runpy.run_path(str(POLICY_SCRIPT))
if policy.get("METHOD_ID") != METHOD_ID:
    fail("policy method identity drift")
if policy.get("METHOD_SHA256") != METHOD_SHA:
    fail("policy method SHA drift")
if policy.get("EXPECTED_METHOD_SHA256") != METHOD_SHA:
    fail("policy pinned expected SHA drift")
if policy.get("REPORT_CONTRACT") != REPORT_CONTRACT:
    fail("priority report contract drift")
if policy.get("EXPLAINABILITY_CONTRACT") != EXPLAINABILITY_CONTRACT:
    fail("priority explainability contract drift")
if manifest.get("method") != policy.get("CANONICAL"):
    fail("frozen canonical method differs from executable canonical method")
if manifest.get("outputColumns") != policy.get("OUTPUT_COLUMNS"):
    fail("frozen output-column contract drift")
if manifest["method"].get("weights") != [] or manifest["method"].get("thresholds") != []:
    fail("frozen V1 must remain weight-free and threshold-free")
if manifest["method"].get("organizationalRisk") is not False:
    fail("frozen V1 must not claim Organizational Risk")

contracts = manifest.get("contracts", {})
if contracts != {
    "report": REPORT_CONTRACT,
    "explainability": EXPLAINABILITY_CONTRACT,
    "priorityHttp": HTTP_CONTRACT,
    "liveBenchmark": LIVE_CONTRACT,
}:
    fail("frozen downstream contract identities drifted")

explainability = manifest.get("explainability", {})
if explainability != {
    "changesPriority": False,
    "rowColumn": "RBVM_MVP_Priority_Explanation",
    "derivation": "DETERMINISTIC_RENDERING_OF_ADMITTED_INPUTS_FRONT_AND_DOMINANCE_COUNTS",
}:
    fail("frozen explainability semantics drifted")

# Freeze the exact deterministic benchmark fixture bytes and expected cases.
if sha256_file(GOLDEN) != GOLDEN_SHA:
    fail(f"golden fixture SHA drift: {sha256_file(GOLDEN)}")
golden = manifest.get("goldenBenchmark", {})
if golden.get("path") != "testdata/rbvm-mvp-priority-golden.csv" or golden.get("sha256") != GOLDEN_SHA:
    fail("golden fixture freeze metadata drift")

with tempfile.TemporaryDirectory(prefix="rbvm-mvp-freeze-") as temp_value:
    temp = Path(temp_value)
    ranked = temp / "ranked.csv"
    report_path = temp / "report.json"
    subprocess.run(
        [sys.executable, str(POLICY_SCRIPT), str(GOLDEN), str(ranked), str(report_path)],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    with ranked.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    report = json.loads(report_path.read_text(encoding="utf-8"))

expected_cases = golden.get("expectedCases", {})
actual_cases = {row["Golden_Case_ID"]: row for row in rows}
if set(actual_cases) != set(expected_cases):
    fail("frozen golden case identity set drift")
for case_id, expected in expected_cases.items():
    row = actual_cases[case_id]
    if row.get("RBVM_MVP_Priority_Status") != expected.get("status"):
        fail(f"{case_id}: frozen priority status drift")
    if row.get("RBVM_MVP_Priority_Front") != expected.get("front"):
        fail(f"{case_id}: frozen Pareto front drift")
    if row.get("RBVM_MVP_Priority_Method_SHA256") != METHOD_SHA:
        fail(f"{case_id}: frozen row method SHA drift")

if report.get("methodId") != METHOD_ID or report.get("methodSha256") != METHOD_SHA:
    fail("golden report policy identity drift")
if report.get("rankedRows") != golden.get("rankedRows"):
    fail("frozen golden ranked-row count drift")
if report.get("unrankableRows") != golden.get("unrankableRows"):
    fail("frozen golden unrankable-row count drift")
if report.get("frontCounts") != golden.get("frontCounts"):
    fail("frozen golden front-count drift")
if report.get("organizationalRiskComputed") is not False or report.get("riskStatus") != "NON_COMPUTABLE":
    fail("frozen policy must not compute Organizational Risk")
if report.get("explainability", {}).get("contractId") != EXPLAINABILITY_CONTRACT:
    fail("golden report explainability identity drift")
if report.get("explainability", {}).get("changesPriority") is not False:
    fail("explainability must remain non-decision-changing")

# The dedicated golden verifier owns row-order-independence and exact explanation
# regression. A freeze is valid only if that oracle still passes independently.
subprocess.run(
    [sys.executable, str(ROOT / "scripts/verify-rbvm-mvp-priority-golden.py")],
    check=True,
    stdout=subprocess.DEVNULL,
)

# Freeze the live benchmark contract to structural invariants rather than live
# provider values, which correctly evolve over time.
live = LIVE.read_text(encoding="utf-8")
for token in [
    "CSV_V2_LIVE_BENCHMARK_V4",
    "EXPECTED_PRIORITY_METHOD_SHA",
    "RBVM_MVP_PRIORITY_POLICY_V1",
    "RBVM_MVP_PRIORITY_EXPLAINABILITY_V1",
    "priority output is not row preserving",
    "benchmark must not infer MAV from Internet Facing",
    "benchmark must not silently compute organizational risk",
    "benchmark must not auto-admit a V2 Organizational Risk method",
]:
    if token not in live:
        fail(f"live benchmark lost frozen invariant {token!r}")

live_manifest = manifest.get("liveBenchmark", {})
if live_manifest.get("script") != "scripts/run-csv-v2-live-benchmark.sh":
    fail("live benchmark script binding drift")
if live_manifest.get("corpus") != "data/benchmarks/cvss4-live-corpus.csv":
    fail("live benchmark corpus binding drift")
if live_manifest.get("customerContext") != "data/benchmarks/cvss4-live-customer-context.json":
    fail("live benchmark customer-context binding drift")
expected_invariants = {
    "ROW_PRESERVING_PRIORITY_OUTPUT",
    "EXACT_PRIORITY_METHOD_ID_AND_SHA",
    "EXPLAINABILITY_CONTRACT_PRESENT",
    "ORGANIZATIONAL_RISK_NON_COMPUTABLE",
    "NO_MAV_INFERENCE_FROM_INTERNET_FACING",
    "NO_V2_PRIMARY_METHOD_AUTO_ADMISSION",
}
if set(live_manifest.get("requiredInvariants", [])) != expected_invariants:
    fail("live benchmark frozen invariant set drift")

# Bind the HTTP transport and deep run visual projection to the same method
# identity; neither may silently advertise another method under V1 routes.
http = HTTP.read_text(encoding="utf-8")
for token in [HTTP_CONTRACT, METHOD_ID, METHOD_SHA, "never claims to", "Organizational Risk"]:
    if token not in http:
        fail(f"priority HTTP contract drift: missing {token!r}")

if RUN_VISUALS.is_file():
    visuals = RUN_VISUALS.read_text(encoding="utf-8")
    for token in ["CSV_RUN_DECISION_VISUALS_V1", METHOD_ID, METHOD_SHA]:
        if token not in visuals:
            fail(f"run decision visual policy binding drift: missing {token!r}")

# Change-control contract itself is frozen: semantic mutation of V1 is forbidden.
change = manifest.get("changeControl", {})
if change.get("semanticChangeRequiresNewMethodVersion") is not True:
    fail("semantic change must require a new method version")
if change.get("forbiddenSilentMutation") is not True:
    fail("silent semantic mutation must remain forbidden")
required_semantic_fields = {
    "dimensions",
    "source-columns",
    "categorical-mappings",
    "dimension-orientation",
    "dominance-rule",
    "fronting-rule",
    "missing-evidence-policy",
    "weights",
    "thresholds",
    "output-semantics",
    "organizational-risk-claim",
}
if set(change.get("semanticFields", [])) != required_semantic_fields:
    fail("semantic change-control field set drift")

freeze_doc = FREEZE_DOC.read_text(encoding="utf-8")
for token in [
    FREEZE_ID,
    "FROZEN_FOR_MVP",
    METHOD_ID,
    METHOD_SHA,
    GOLDEN_SHA,
    "RBVM_MVP_PRIORITY_POLICY_V2",
    "semantic methodology change",
    "Organizational Risk = NON_COMPUTABLE",
    "weights = []",
    "thresholds = []",
]:
    if token not in freeze_doc:
        fail(f"freeze documentation missing {token!r}")

policy_doc = POLICY_DOC.read_text(encoding="utf-8")
if METHOD_ID not in policy_doc or METHOD_SHA not in policy_doc:
    fail("primary policy documentation identity drift")

print("RBVM MVP Priority Policy V1 methodology freeze: PASS")
