#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "api/openapi.yaml"
text = path.read_text(encoding="utf-8")
marker = "  /risk-method-selection-policies/{revision}/{policySha256}:\n"
block = """  /risk-method-selection-policy-activation/current:\n    $ref: './risk-method-selection-policy-activation-v1.openapi.yaml#/paths/~1api~1v1~1risk-method-selection-policy-activation~1current'\n  /risk-method-selection-policy-activations/{activationRevision}/{eventSha256}:\n    $ref: './risk-method-selection-policy-activation-v1.openapi.yaml#/paths/~1api~1v1~1risk-method-selection-policy-activations~1{activationRevision}~1{eventSha256}'\n  /risk-method-selection-policy-activation-events/{activationRevision}/ACTIVE/{policyRevision}/{policySha256}/{recordedAt}:\n    $ref: './risk-method-selection-policy-activation-v1.openapi.yaml#/paths/~1api~1v1~1risk-method-selection-policy-activation-events~1{activationRevision}~1ACTIVE~1{policyRevision}~1{policySha256}~1{recordedAt}'\n  /risk-method-selection-policy-activation-events/{activationRevision}/CLEARED/{recordedAt}:\n    $ref: './risk-method-selection-policy-activation-v1.openapi.yaml#/paths/~1api~1v1~1risk-method-selection-policy-activation-events~1{activationRevision}~1CLEARED~1{recordedAt}'\n"""
needles = (
    "/risk-method-selection-policy-activation/current:",
    "/risk-method-selection-policy-activations/{activationRevision}/{eventSha256}:",
    "/risk-method-selection-policy-activation-events/{activationRevision}/ACTIVE/{policyRevision}/{policySha256}/{recordedAt}:",
    "/risk-method-selection-policy-activation-events/{activationRevision}/CLEARED/{recordedAt}:",
)
if all(needle in text for needle in needles):
    print("combined OpenAPI already contains exact activation paths")
else:
    if any(needle in text for needle in needles):
        raise SystemExit("partial activation OpenAPI patch detected")
    if text.count(marker) != 1:
        raise SystemExit("policy path insertion marker is not unique")
    path.write_text(text.replace(marker, block + marker, 1), encoding="utf-8")
    print("combined OpenAPI patched with exact activation paths")
