# CVSS v4 Official Engine V1

Contract ID: `CVSS_V4_OFFICIAL_ENGINE_V1`

## Purpose

This engine calculates **CVSS v4.0 technical severity** only. It does not calculate Organizational Risk, Priority, Treatment, or SLA.

Implementation: `scripts/cvss_v4_official.py`

The implementation is a dependency-free Python port of the FIRST CVSS v4.0 reference calculator scoring algorithm and MacroVector lookup data.

Reference repository:

- `FIRSTdotorg/cvss-v4-calculator`
- reference commit observed for this implementation: `c5b0d409ae9f57c44264c6ce5f27d89298e1d32a`
- reference code/data license: BSD-2-Clause

The engine is verified against FIRST-published example vectors in `scripts/verify-cvss-v4-official.py`.

## CSV-first calculation boundary

For a resolved CVSS v4 Base assessment:

1. Recalculate Base from `AV/AC/AT/PR/UI/VC/VI/VA/SC/SI/SA`.
2. Compare the recalculated Base score with the published Base score.
3. Preserve a published Threat `E` value when consistent with current evidence.
4. If Threat `E` is not published and CISA KEV is `LISTED`, resolve `E:A` (`Attacked`).
5. If a published non-`A` Threat value conflicts with KEV listing, emit `AMBIGUOUS_THREAT_CONFLICT`; do not silently overwrite it.
6. If no Threat metric is assessed, calculate and label `CVSS-B`.
7. If Threat `E` is assessed/resolved, calculate and label `CVSS-BT`.

The engine does **not** use customer Asset Criticality or customer `Internet Facing` to synthesize CVSS Environmental metrics.

Current MVP Environmental behavior remains:

```text
CR = X
IR = X
AR = X
MAV = X
```

until semantically matching organization-specific evidence is available under an explicit versioned resolver contract.

## Output fields

CSV enrichment materializes:

```text
CVSS4_Base_Score_Calculated
CVSS4_Base_Score_Validation
CVSS4_Calculated_Status
CVSS4_Calculated_Nomenclature
CVSS4_Calculated_Vector
CVSS4_Calculated_Score
CVSS4_Calculated_Severity
CVSS4_Calculated_Macro_Vector
CVSS4_Threat_E_Resolution
```

`CVSS4_Base_Score_Validation=MISMATCH` is evidence of a published-score/vector inconsistency and must not be silently normalized away.

## Important FIRST scoring semantic

For score calculation, CVSS v4 treats Threat `E:X` as the worst-case default equivalent to `E:A`. Therefore resolving previously undefined Threat evidence to `E:A` can change provenance and nomenclature from `CVSS-B` to `CVSS-BT` without necessarily changing the numeric score.

## Separation from RBVM Formula V2

The resulting CVSS-B/CVSS-BT score remains technical vulnerability severity. EPSS remains exploitation probability; KEV/SSVC remain threat evidence; Asset Criticality and Internet Facing remain customer context.

No multiplication, weighted sum, or other composition of those dimensions into Organizational Risk is performed by this engine.
