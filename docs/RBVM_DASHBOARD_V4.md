# RBVM Dashboard V4 — Standards-Oriented Visual Decision View

Contract: `RBVM_DASHBOARD_V4_STANDARDS_VIEW`

## Purpose

Dashboard V4 turns the RBVM overview into a visual decision surface while preserving the boundaries of the underlying standards and evidence models. No chart is allowed to create a new risk meaning that the source evidence does not support.

## Standards basis

The visual model is informed by:

- NIST CSF 2.0: understand, assess, prioritize, and communicate cybersecurity risk outcomes; threats, vulnerabilities, likelihoods, and impacts should inform risk response prioritization.
- NIST IR 8286 Rev. 1 / IR 8286A Rev. 1: risk communication should preserve likelihood, impact, enterprise context, and risk response information rather than collapse inputs without an explicit methodology.
- NIST IR 8286D Update 1: asset criticality and mission/business impact are distinct context inputs derived from business impact analysis.
- NIST SP 800-40 Rev. 4: patch management includes identifying, prioritizing, applying, and verifying remediation; historical response metrics require defensible lifecycle state.
- CISA KEV: confirmed exploitation in the wild is an explicit input to vulnerability-management prioritization.
- CISA SSVC: prioritization is a decision process, not a synonym for CVSS severity.
- FIRST CVSS v4.0: Base, Threat, Environmental, and Supplemental metrics have separate purposes; CVSS is an input to organizational vulnerability management, not an enterprise risk score.
- FIRST EPSS: EPSS is a calibrated probability of exploitation in the next 30 days; it remains separate from CVSS and direct exploitation evidence.

## Visual layers

### Technical severity

A severity donut shows the current technical-severity distribution. It does not label the output as enterprise risk.

### Confirmed exploitation

A KEV donut shows findings with confirmed exploitation separately from findings that are not listed or not established as listed. Absence from KEV is not labeled safe or non-exploitable.

### CVSS × EPSS decision landscape

A scatter plot places EPSS probability on the x-axis and CVSS technical severity on the y-axis. The values are not multiplied. KEV-listed findings are highlighted as direct exploitation evidence.

### Severity × KEV matrix

A heatmap intersects two finding-level signals that can be joined defensibly from the same canonical case object: technical severity and KEV status.

### EPSS ranking

A ranked bar chart shows the highest native EPSS probabilities. V4 does not invent a universal EPSS threshold.

### Asset concentration

A horizontal bar chart shows findings per observed asset. Concentration is described as operational exposure, not mission impact.

### Finding age

Age buckets use explicit first-observed timestamps. Age is shown as backlog context and is not converted to priority automatically.

### Asset criticality

A separate donut visualizes customer-declared managed-asset criticality. V4 deliberately does not join criticality to a finding by asset-name inference.

### Decision readiness

Coverage rings show CVSS, EPSS, and KEV availability. Missing evidence remains visible information and is never treated as zero.

### Treatment priority

Priority is visualized only if an explicit priority field is present in the consumed API. V4 never derives a priority front from CVSS, EPSS, KEV, age, or asset criticality.

### Historical response trend

New / Remediated / Active and remediation effectiveness are intentionally withheld until an immutable historical aggregation API exists. Current-state survivor data is not used to fabricate lifecycle trends.

## Prohibited semantics

Dashboard V4 must not:

- multiply CVSS by EPSS;
- infer Asset Criticality from vulnerability severity;
- infer finding-to-managed-asset association from matching names;
- describe KEV absence as non-exploitable or safe;
- invent EPSS thresholds as standards requirements;
- invent treatment SLA values;
- reconstruct remediation trends from current-state survivors;
- claim Organizational Risk without an explicit risk methodology and required business context.
