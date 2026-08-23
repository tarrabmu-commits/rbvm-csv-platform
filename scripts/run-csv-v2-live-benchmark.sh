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
BENCHMARK_SUMMARY="$OUT_DIR/benchmark-summary.json"

python3 "$ROOT_DIR/scripts/enrich-uploaded-csv.py" \
  "$CORPUS" "$ENRICHED" \
  --snapshot-output "$SNAPSHOT" \
  --report "$ENRICH_REPORT" \
  --collector-report "$COLLECTOR_REPORT"

python3 "$ROOT_DIR/scripts/analyze-csv-run-evidence.py" \
  "$ENRICHED" "$ANALYSIS" "$ANALYSIS_SUMMARY" \
  --customer-bundle "$CONTEXT"

python3 - "$CORPUS" "$CONTEXT" "$ENRICH_REPORT" "$ANALYSIS" "$ANALYSIS_SUMMARY" "$BENCHMARK_SUMMARY" <<'PY'
import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

corpus, context, enrich_report, analysis_csv, analysis_summary, output = map(Path, sys.argv[1:])


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
enrichment = json.loads(enrich_report.read_text(encoding='utf-8'))

base_validation = Counter(str(r.get('CVSS4_Base_Score_Validation') or 'NOT_APPLICABLE') for r in rows)
calc_status = Counter(str(r.get('CVSS4_Calculated_Status') or 'NOT_CALCULATED') for r in rows)
nomenclature = Counter(str(r.get('CVSS4_Calculated_Nomenclature') or 'NONE') for r in rows)
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
        'calculatedStatus': r.get('CVSS4_Calculated_Status'),
        'nomenclature': r.get('CVSS4_Calculated_Nomenclature'),
        'calculatedScore': r.get('CVSS4_Calculated_Score'),
        'calculatedSeverity': r.get('CVSS4_Calculated_Severity'),
        'threatEResolution': r.get('CVSS4_Threat_E_Resolution'),
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
calculated = sum(r.get('CVSS4_Calculated_Status') == 'CALCULATED' for r in rows)

result = {
    'contractId': 'CSV_V2_LIVE_BENCHMARK_V1',
    'semantics': 'LIVE_PUBLIC_INTELLIGENCE_PLUS_SYNTHETIC_ORGANIZATION_CONTEXT',
    'inputCorpusSha256': sha256_file(corpus),
    'customerContextSha256': sha256_file(context),
    'observedAt': enrichment.get('observedAt'),
    'publicIntelSnapshotSha256': enrichment.get('publicIntelSnapshotSha256'),
    'scope': {
        'findingRows': len(rows),
        'uniqueCves': len({r.get('CVE_ID') for r in rows if r.get('CVE_ID')}),
    },
    'coverage': {
        'cvss4Status': dict(sorted(cvss_status.items())),
        'cvss4CalculatedStatus': dict(sorted(calc_status.items())),
        'baseScoreValidation': dict(sorted(base_validation.items())),
        'calculatedNomenclature': dict(sorted(nomenclature.items())),
        'epssPresentRows': epss_present,
        'kevListedRows': kev_listed,
        'cisaSsvcPresentRows': ssvc_present,
        'customerContextMatchedRows': matched,
        'customerContextStatus': dict(sorted(context_status.items())),
    },
    'rows': row_view,
    'rbvmV2': {
        'status': analysis.get('rbvmV2', {}).get('status'),
        'riskComputedRows': analysis.get('rbvmV2', {}).get('riskComputedRows'),
        'reason': analysis.get('rbvmV2', {}).get('reason'),
        'benchmarkDecision': 'EVIDENCE_PIPELINE_MEASURABLE_ORGANIZATIONAL_RISK_COMPOSITION_STILL_UNAPPROVED',
    },
}

if len(rows) != 6:
    raise SystemExit(f'benchmark corpus row count changed unexpectedly: {len(rows)}')
if matched != len(rows):
    raise SystemExit(f'customer context join incomplete: {matched}/{len(rows)}')
if calculated < 3:
    raise SystemExit(f'expected at least 3 live CVSS v4 calculations, got {calculated}')
if epss_present < 5:
    raise SystemExit(f'expected EPSS on at least 5 rows, got {epss_present}')
if kev_listed < 2:
    raise SystemExit(f'expected at least 2 KEV-listed rows, got {kev_listed}')
if analysis.get('rbvmV2', {}).get('riskComputedRows') != 0:
    raise SystemExit('benchmark must not silently compute organizational risk')

output.write_text(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + '\n', encoding='utf-8')
print(json.dumps(result, sort_keys=True))
PY

sha256sum "$CORPUS" "$CONTEXT" "$ENRICHED" "$SNAPSHOT" "$ANALYSIS" "$BENCHMARK_SUMMARY" > "$OUT_DIR/SHA256SUMS"
printf '%s\n' "CSV V2 live benchmark: PASS output=$OUT_DIR"
