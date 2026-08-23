# RBVM Dashboard V5 — Lifecycle and Semantic Guardrails

Contract: `RBVM_DASHBOARD_V5_LIFECYCLE_VIEW`

## Purpose

Dashboard V5 extends the standards-oriented V4 Overview with defensible workflow and time-oriented visuals without reconstructing unsupported remediation history.

The view follows the same evidence separation used throughout RBVM:

- technical severity remains separate from threat probability;
- confirmed exploitation remains separate from prediction;
- workflow disposition remains separate from remediation verification;
- customer SLA remains separate from CISA KEV federal reference dates;
- treatment priority must come from an explicit admitted methodology;
- legacy threshold heuristics are never presented as the current RBVM priority method.

## Included visuals

### Current workflow state

A donut visualization shows the exact current canonical case states:

- `OPEN`
- `SOURCE_RESOLVED`
- `ACCEPTED_RISK`
- `FALSE_POSITIVE`
- `CLOSED_MANUAL`

The dashboard does not rename `SOURCE_RESOLVED` or `CLOSED_MANUAL` to `Remediated`. Verified remediation requires stronger lifecycle evidence than a presentation layer may infer.

### First-observed cohorts

A twelve-week bar chart shows how many retained canonical cases were first observed in each week.

This is a discovery/detection cadence visual only. It is not an `Active / New / Remediated` backlog trend, because the latter requires immutable historical state for every reporting date.

### Vulnerability-intelligence freshness

A donut view deduplicates current cases by CVE and classifies intelligence as:

- fresh inside the canonical `freshnessWindowHours`;
- stale;
- missing.

Missing or stale intelligence remains visible and is not converted to a lower risk or priority value.

### CISA KEV due-date reference

For unique KEV-listed CVEs, Dashboard V5 groups CISA due dates into reference windows.

These dates originate from U.S. federal Binding Operational Directive 22-01 requirements. RBVM displays them only as external reference data. They are not silently converted into a customer SLA, remediation deadline, or compliance result.

## Legacy intelligence heuristic guardrail

The original V2 vulnerability-intelligence model exposed a convenience `priorityTier` derived from fixed thresholds over KEV, EPSS, and CVSS.

That classifier predates `RBVM_MVP_PRIORITY_POLICY_V1` and is not the current RBVM treatment-priority methodology.

For backward compatibility, the API keeps the historic fields but now labels them explicitly with:

- `priorityTierDeprecated = true`
- `priorityTierSemantics = LEGACY_REFERENCE_ONLY_NOT_RBVM_MVP_PRIORITY_OR_ORGANIZATIONAL_RISK`
- `legacyHeuristicTier`
- `legacyHeuristicId = LEGACY_V2_INTELLIGENCE_PRIORITY_HEURISTIC_V1`

The aggregate catalog summary likewise exposes explicit deprecation/semantics metadata around `priorityDistribution`.

Dashboard V5 does not consume the legacy heuristic as treatment priority.

## Standards alignment

The visual boundaries are consistent with the project’s documented use of:

- NIST CSF 2.0 for current risk and exposure understanding;
- NIST IR 8286 family for keeping mission/business context distinct from technical vulnerability signals;
- NIST SP 800-40 Rev. 4 for vulnerability/patch-management lifecycle discipline;
- CISA KEV for confirmed exploitation evidence and external federal remediation-reference dates;
- FIRST CVSS and EPSS as separate technical-severity and exploitation-probability signals.

## Explicit non-claims

Dashboard V5 does **not**:

- calculate Organizational Risk;
- calculate `CVSS × EPSS`;
- convert age to priority;
- convert CISA KEV due dates into customer SLA compliance;
- infer remediation from disappearance or current status labels;
- treat the legacy V2 heuristic as `RBVM_MVP_PRIORITY_POLICY_V1`;
- fabricate `New / Remediated / Active` historical series.
