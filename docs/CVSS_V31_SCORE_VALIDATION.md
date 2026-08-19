# CVSS v3.1 Base Score / Vector Consistency

`CVSS_V31_CSV_V1` treats the published Base score and vector as one evidence statement. A row is not accepted merely because the score is in `0.0..10.0` and the vector is syntactically valid: the numeric Base score must be the score produced by the eight Base metrics in that vector.

## Why this is required

The CVSS v3.1 specification defines the Base score as a deterministic result of the Base metrics. Accepting a mismatched pair such as:

```text
CVSS_Base_Score = 7.5
CVSS_Vector     = CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

would preserve contradictory evidence. That vector produces `9.8`, not `7.5`, so the row is quarantined as an invalid Base-score field.

## Implemented equations

`CvssV31BaseScoreCalculator` implements the FIRST CVSS v3.1 Base equations only:

```text
ISS = 1 - ((1-C) * (1-I) * (1-A))

Impact, Scope Unchanged = 6.42 * ISS
Impact, Scope Changed   = 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02)^15

Exploitability = 8.22 * AV * AC * PR * UI
```

If Impact is not positive, Base Score is `0.0`. Otherwise the result is capped at `10.0`; Scope Changed applies the specification's `1.08` multiplier before the final cap and Roundup.

Privileges Required uses the scope-dependent CVSS v3.1 weights. All weights are the constants published by FIRST for CVSS v3.1.

The implementation uses `BigDecimal` decimal arithmetic and a one-decimal `CEILING` operation for the positive final result. This directly implements the specification's Roundup semantics while avoiding binary floating-point boundary noise.

## Validation behavior

At the `CvssV31BaseEvidence` boundary:

```text
valid vector + matching score
    -> accepted

valid vector + non-matching score
    -> quarantined
       INVALID_CVSS_BASE_SCORE
```

Metric order remains semantically irrelevant. The calculator receives the already validated eight Base metrics, so Temporal and Environmental metrics remain outside this contract.

## Reference checks

Self-tests include published FIRST v3.1 examples and formula-sensitive cases, including:

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8
CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H -> 8.1
CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H -> 7.8
```

They also cover Scope Changed and zero-impact behavior.

## Methodology boundary

This validation strengthens Technical Severity evidence only. It does not introduce or infer:

```text
Priority
Risk Score
EPSS
CISA KEV
Asset Criticality
Business Impact
SLA
RBVM Decision
```

A mathematically valid CVSS Base score is still severity evidence, not organizational risk.
