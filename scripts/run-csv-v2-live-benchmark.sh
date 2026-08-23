#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/build/csv-v2-live-benchmark}"
CORPUS="$ROOT_DIR/data/benchmarks/cvss4-live-corpus.csv"
CONTEXT="$ROOT_DIR/data/benchmarks/cvss4-live-customer-context.json"

mkdir -p "$OUT_DIR"
rm -f "$OUT_DIR"/*

ENRICHED="$OUT_DIR/enriched.csv"
SNAPSHOT="$OUT_DIR/public-intel.json"
ENRICH_REPORT="$OUT_DIR/enrichment-report.json"
COLLECTOR_REPORT="$OUT_DIR/collector-report.json"
ANALYSIS="$OUT_DIR/analysis.csv"
ANALYSIS_SUMMARY="$OUT_DIR/analysis-summary.json"
ADMISSION_REPORT="$OUT_DIR/method-admission.json"
BENCHMARK_SUMMARY="$OUT_DIR/benchmark-summary.json"

python3 "$ROOT_DIR/scripts/enrich-uploaded-csv.py" \
  "$CORPUS" "$ENRICHED" \
  --snapshot-output "$SNAPSHOT" \
  --report "$ENRICH_REPORT" \
  --collector-report "$COLLECTOR_REPORT"

python3 "$ROOT_DIR/scripts/analyze-csv-run-evidence.py" \
  "$ENRICHED" "$ANALYSIS" "$ANALYSIS_SUMMARY" \
  --customer-bundle "$CONTEXT"

python3 "$ROOT_DIR/scripts/evaluate-rbvm-v2-method-candidates.py" \
  "$ANALYSIS" "$ADMISSION_REPORT"

python3 - "$CORPUS" "$CONTEXT" "$ENRICH_REPORT" "$ANALYSIS" "$ANALYSIS_SUMMARY" "$ADMISSION_REPORT" "$BENCHMARK_SUMMARY" <<'PY'
import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

corpus, context, enrich_report, analysis_csv, analysis_summary, admission_report, output = map(Path, sys.argv[1:])


def sha256_file(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def truthy(value):
    return str(value or '').strip().lower() in {'true', '1', 'yes', 'listed'}

with analysis_csv.open('r', encoding='utf-8-sig', newline='') as f:
    rows = list(csv.DictReader(f))
analysis = json.loads(analysis_summary.read_text(encoding='utf-8'))
admission = json.loads(admission_report.read_text(encoding='utf-8'))
enrichment = json.loads(enrich_report.read_text(encoding='utf-8'))

base_validation = Counter(str(r.get('CVSS4_Base_Score_Validation') or 'NOT_APPLICABLE') for r in rows)
calc_status = Counter(str(r.get('CVSS4_Calculated_Status') or 'NOT_CALCULATED') for r in rows)
public_nomenclature = Counter(str(r.get('CVSS4_Calculated_Nomenclature') or 'NONE') for r in rows)
context_nomenclature = Counter(str(r.get('CVSS4_Context_Nomenclature') or 'NONE') for r in rows)
environmental_status = Counter(str(r.get('CVSS4_Environmental_Requirement_Status') or 'NONE') for r in rows)
cvss_status = Counter(str(r.get('CVSS4_Status') or 'MISSING') for r in rows)
context_status = Counter(str(r.get('Customer_Context_Status') or 'MISSING') for r in rows)

row_view = []
for r in rows:
    row_view.append({
        'cveId': r.get('CVE_ID'),
        'asset': r.get('Agent') or r.get('Agent_ID'),
        'cvss4Status': r.get('CVSS4_Status'),
        'publishedBaseScore': r.get('CVSS4_Base_Score'),
        'calculatedBaseScore': r.get('CVSS4_Base_Score_Calculated'),
        'baseScoreValidation': r.get('CVSS4_Base_Score_Validation'),
        'publicCalculatedStatus': r.get('CVSS4_Calculated_Status'),
        'publicNomenclature': r.get('CVSS4_Calculated_Nomenclature'),
        'publicScore': r.get('CVSS4_Calculated_Score'),
        'publicSeverity': r.get('CVSS4_Calculated_Severity'),
        'threatEResolution': r.get('CVSS4_Threat_E_Resolution'),
        'cr': r.get('CVSS4_CR_Resolved'),
        'ir': r.get('CVSS4_IR_Resolved'),
        'ar': r.get('CVSS4_AR_Resolved'),
        'mav': r.get('CVSS4_MAV_Resolved'),
        'environmentalRequirementStatus': r.get('CVSS4_Environmental_Requirement_Status'),
        'environmentalRequirementSource': r.get('CVSS4_Environmental_Requirement_Source'),
        'contextMode': r.get('CVSS4_Context_Mode'),
        'contextScoreStatus': r.get('CVSS4_Context_Score_Status'),
        'contextNomenclature': r.get('CVSS4_Context_Nomenclature'),
        'contextScore': r.get('CVSS4_Context_Score'),
        'contextSeverity': r.get('CVSS4_Context_Severity'),
        'epssProbability': r.get('EPSS_Probability'),
        'epssPercentile': r.get('EPSS_Percentile'),
        'kevListed': r.get('KEV_Listed'),
        'cisaExploitation': r.get('CISA_Exploitation'),
        'cisaAutomatable': r.get('CISA_Automatable'),
        'cisaTechnicalImpact': r.get('CISA_Technical_Impact'),
        'assetCriticality': r.get('Asset_Criticality'),
        'internetFacing': r.get('Internet_Facing'),
        'customerContextStatus': r.get('Customer_Context_Status'),
        'rbvmV2Status': r.get('RBVM_V2_Status'),
    })

matched = sum(r.get('Customer_Context_Status') in {'MATCHED_KEY', 'MATCHED_NAME'} for r in rows)
epss_present = sum(bool(str(r.get('EPSS_Probability') or '').strip()) for r in rows)
kev_listed = sum(truthy(r.get('KEV_Listed')) for r in rows)
ssvc_present = sum(any(str(r.get(k) or '').strip() for k in ('CISA_Exploitation', 'CISA_Automatable', 'CISA_Technical_Impact')) for r in rows)
public_calculated = sum(r.get('CVSS4_Calculated_Status') == 'CALCULATED' for r in rows)
contextual_calculated = sum(r.get('CVSS4_Context_Score_Status') == 'CALCULATED_FIRST_REFERENCE_COMPATIBLE' for r in rows)
environmental_defined = sum(r.get('CVSS4_Environmental_Requirement_Status') in {'PARTIAL', 'COMPLETE'} for r in rows)

candidate_states = {
    (candidate.get('methodId') or 'UNDEFINED_V2'): candidate.get('admissionState')
    for candidate in admission.get('candidates', [])
}

result = {
    'contractId': 'CSV_V2_LIVE_BENCHMARK_V3',
    'semantics': 'LIVE_PUBLIC_INTELLIGENCE_PLUS_SYNTHETIC_DIRECT_CVSS_ENVIRONMENTAL_REQUIREMENTS_PLUS_RISK_METHOD_ADMISSION',
    'inputCorpusSha256': sha256_file(corpus),
    'customerContextSha256': sha256_file(context),
    'observedAt': enrichment.get('observedAt'),
    'publicIntelSnapshotSha256': enrichment.get('publicIntelSnapshotSha256'),
    'methodAdmissionReportSha256': admission.get('reportSha256'),
    'scope': {
        'findingRows': len(rows),
        'uniqueCves': len({r.get('CVE_ID') for r in rows if r.get('CVE_ID')}),
    },
    'coverage': {
        'cvss4Status': dict(sorted(cvss_status.items())),
        'cvss4CalculatedStatus': dict(sorted(calc_status.items())),
        'baseScoreValidation': dict(sorted(base_validation.items())),
        'publicNomenclature': dict(sorted(public_nomenclature.items())),
        'contextNomenclature': dict(sorted(context_nomenclature.items())),
        'environmentalRequirementStatus': dict(sorted(environmental_status.items())),
        'environmentalRequirementDefinedRows': environmental_defined,
        'contextualCvssCalculatedRows': contextual_calculated,
        'epssPresentRows': epss_present,
        'kevListedRows': kev_listed,
        'cisaSsvcPresentRows': ssvc_present,
        'customerContextMatchedRows': matched,
        'customerContextStatus': dict(sorted(context_status.items())),
    },
    'methodAdmission': {
        'state': admission.get('selection', {}).get('state'),
        'riskComputedRows': admission.get('selection', {}).get('riskComputedRows'),
        'candidateStates': dict(sorted(candidate_states.items())),
        'csvFirstCapability': admission.get('csvFirstCapability'),
    },
    'rows': row_view,
    'rbvmV2': {
        'status': analysis.get('rbvmV2', {}).get('status'),
        'riskComputedRows': analysis.get('rbvmV2', {}).get('riskComputedRows'),
        'reason': analysis.get('rbvmV2', {}).get('reason'),
        'benchmarkDecision': 'CONTEXTUAL_CVSS_IS_COMPUTABLE_BUT_NO_V2_ORGANIZATIONAL_RISK_METHOD_IS_ADMITTED',
    },
}

output.write_text(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + '\n', encoding='utf-8')
print(json.dumps(result, sort_keys=True))

if len(rows) != 6:
    raise SystemExit(f'benchmark corpus row count changed unexpectedly: {len(rows)}')
if matched != len(rows):
    raise SystemExit(f'customer context join incomplete: {matched}/{len(rows)}')
if public_calculated < 3:
    raise SystemExit(f'expected at least 3 live CVSS v4 calculations, got {public_calculated}')
if contextual_calculated < public_calculated:
    raise SystemExit(f'contextual CVSS projection lost calculated rows: {contextual_calculated}/{public_calculated}')
if environmental_defined < 4:
    raise SystemExit(f'expected direct synthetic CR/IR/AR on at least 4 rows, got {environmental_defined}')
if context_nomenclature.get('CVSS-BE', 0) < 1:
    raise SystemExit('expected at least one live CVSS-BE result from direct CR/IR/AR')
if context_nomenclature.get('CVSS-BTE', 0) < 2:
    raise SystemExit('expected at least two live CVSS-BTE results from Threat + direct CR/IR/AR')
if epss_present < 5:
    raise SystemExit(f'expected EPSS on at least 5 rows, got {epss_present}')
if kev_listed < 2:
    raise SystemExit(f'expected at least 2 KEV-listed rows, got {kev_listed}')
if any(r.get('CVSS4_MAV_Resolved') != 'X' for r in rows):
    raise SystemExit('benchmark must not infer MAV from Internet Facing')
if analysis.get('rbvmV2', {}).get('riskComputedRows') != 0:
    raise SystemExit('benchmark must not silently compute organizational risk')
if admission.get('selection', {}).get('state') != 'NO_V2_PRIMARY_METHOD_ADMITTED':
    raise SystemExit('benchmark must not auto-admit a V2 Organizational Risk method')
if admission.get('selection', {}).get('riskComputedRows') != 0:
    raise SystemExit('method admission must not emit risk numbers')
if candidate_states.get('CVSS_V4_CONTEXTUAL_SEVERITY') != 'NOT_A_RISK_METHOD':
    raise SystemExit('contextual CVSS must remain evidence, not a risk method')
if candidate_states.get('RBVM_FORMULA_V1') != 'LEGACY_REFERENCE_ONLY':
    raise SystemExit('Formula V1 must remain legacy reference for CSV-first V2')
if candidate_states.get('OWASP_DERIVED_RBVM_V1') != 'BLOCKED_INPUT_CONTRACT':
    raise SystemExit('OWASP-derived V1 must remain blocked without exact Decision Input V3')
if candidate_states.get('MICROSOFT_PD_DERIVED_RBVM_V1') != 'BLOCKED_INPUT_CONTRACT':
    raise SystemExit('Microsoft-derived V1 must remain blocked without exact Decision Input V3')
PY

sha256sum "$CORPUS" "$CONTEXT" "$ENRICHED" "$SNAPSHOT" "$ANALYSIS" "$ADMISSION_REPORT" "$BENCHMARK_SUMMARY" > "$OUT_DIR/SHA256SUMS"
printf '%s\n' "CSV V2 live benchmark: PASS output=$OUT_DIR"
