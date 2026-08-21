#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SPA_ASSERTIONS = '''            assert ui.statusCode() == 200 : ui.body();
            assert ui.body().contains("<html lang=\\\"en\\\" dir=\\\"ltr\\\">");
            assert ui.body().contains("id=\\\"rbvm-app\\\"");
            assert ui.body().contains("/ui/rbvm-ui.js");'''

REPLACEMENTS = {
    "CsvCvssV31HttpSelfTest.java": (
        '''            assert ui.statusCode() == 200 : ui.body();
            assert ui.body().contains("CVSS_V31_CSV_V1");
            assert ui.body().contains("Technical Severity");''',
        SPA_ASSERTIONS,
    ),
    "CsvCisaKevHttpSelfTest.java": (
        '''            assert ui.statusCode() == 200 : ui.body();
            assert ui.body().contains("CISA_KEV_CSV_V1");
            assert ui.body().contains("NOT_LISTED");''',
        SPA_ASSERTIONS,
    ),
    "CsvEpssHttpSelfTest.java": (
        '''            assert ui.statusCode() == 200 : ui.body();
            assert ui.body().contains("EPSS_CSV_V1");
            assert ui.body().contains("Probability");
            assert !ui.body().contains("EPSS &gt;=");''',
        SPA_ASSERTIONS,
    ),
    "CsvAssetContextHttpSelfTest.java": (
        '''            assert ui.statusCode() == 200 : ui.body();
            assert ui.body().contains("ASSET_CONTEXT_CSV_V1");
            assert ui.body().contains("Business Criticality");
            assert ui.body().contains("qualitative evidence");
            assert !ui.body().contains("criticalityWeight");
            assert !ui.body().contains("riskScore");
            assert !ui.body().contains("priorityTier");''',
        SPA_ASSERTIONS,
    ),
    "CsvNetworkReachabilityHttpSelfTest.java": (
        '''            assert ui.statusCode() == 200 : ui.body();
            assert ui.body().contains("NETWORK_REACHABILITY_CSV_V1");
            assert ui.body().contains("NOT_REACHABLE");
            assert ui.body().contains("مو إثبات إن الـasset معزول عالمياً");
            assert !ui.body().contains("riskScore");
            assert !ui.body().contains("priorityTier");
            assert !ui.body().contains("internetExposed");''',
        SPA_ASSERTIONS,
    ),
    "CsvBusinessImpactHttpSelfTest.java": (
        '''            assert ui.statusCode() == 200 : ui.body();
            assert ui.body().contains("BUSINESS_IMPACT_CSV_V1");
            assert ui.body().contains("SEVERE/HIGH/...");
            assert ui.body().contains("ما في mapping تلقائي بين MISSION_CRITICAL وSEVERE");
            assert !ui.body().contains("riskScore");
            assert !ui.body().contains("priorityTier");
            assert !ui.body().contains("impactWeight");''',
        SPA_ASSERTIONS,
    ),
}

base = ROOT / "src/test/java/io/rbvm/csv"
for name, (old, new) in REPLACEMENTS.items():
    path = base / name
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{name}: expected exactly one legacy UI assertion block, found {count}")
    path.write_text(text.replace(old, new), encoding="utf-8")

print(f"frontend_v2_http_smoke_repair=APPLIED files={len(REPLACEMENTS)}")
