#!/usr/bin/env python3
"""Apply the current CSV-first customer-risk input scope to the compiled frontend.

The persisted RBVM_CUSTOMER_ASSET_BUNDLE_V4 contract remains backward compatible and
continues to carry Publicly Exposed and CVSS CR/IR/AR as UNKNOWN/X when they are not
customer-declared. The current product workflow deliberately asks the customer for only:
Asset Criticality and Internet Facing.

This is a fail-closed compile-time transform: every expected legacy UI block must be
present exactly once or the build fails rather than silently shipping a mixed scope.
"""

from __future__ import annotations

import sys
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one anchor, found {count}")
    return text.replace(old, new, 1)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: apply-current-risk-input-scope-ui.py <compiled-rbvm-ui.js>")
    path = Path(sys.argv[1])
    text = path.read_text(encoding="utf-8")

    text = replace_once(
        text,
        "Automatic: CVSS v4 Base, EPSS, KEV, CISA SSVC, CWE/CPE and provenance. Customer: Asset Criticality, legacy Internet Facing, explicit CISA Publicly Exposed, and optional direct CVSS CR/IR/AR requirements.",
        "Automatic: CVSS v4 Base, EPSS, KEV, CISA SSVC, CWE/CPE and provenance. Customer: Asset Criticality and Internet Facing only.",
        "import-scope",
    )
    text = replace_once(
        text,
        "const key = textInput(asset.customerAssetKey || '', 'Stable customer key', 'customerAssetKey');\n    const name = textInput(asset.displayName || '', 'Asset name', 'displayName');",
        "const key = textInput(asset.customerAssetKey || '', 'Stable customer key', 'customerAssetKey'); key.readOnly = true;\n    const name = textInput(asset.displayName || '', 'Asset name', 'displayName'); name.readOnly = true;",
        "asset-identity-readonly",
    )
    text = replace_once(
        text,
        "el('div', {class: 'form-grid'},\n          field('Asset ID', key), field('Asset Name', name), field('Asset Criticality', criticality), field('Internet Facing?', internet),\n          field('CISA Publicly Exposed?', publiclyExposed), field('Confidentiality Requirement (CVSS CR)', cr),\n          field('Integrity Requirement (CVSS IR)', ir), field('Availability Requirement (CVSS AR)', ar)\n        ),\n        callout('CISA Publicly Exposed is an explicit BOD 26-04 customer decision point. Internet Facing is legacy/coarse context and never populates it. UNKNOWN is preserved when not assessed.'),\n        callout('CR/IR/AR are direct CVSS v4 Security Requirements. They are not derived from Asset Criticality. X means Not Defined.'),",
        "el('div', {class: 'form-grid'},\n          field('Asset ID', key), field('Asset Name', name), field('Asset Criticality', criticality), field('Internet Facing?', internet)\n        ),\n        callout('For the current RBVM risk workflow, the customer provides only Asset Criticality and Internet Facing. Asset identity is read-only evidence from the uploaded CSV. Legacy V4 fields remain UNKNOWN/X unless a previously saved bundle already contains them.'),",
        "asset-editor-scope",
    )
    text = replace_once(
        text,
        "el('div', {class: 'inline-actions', style: 'margin-top:12px'}, remove)",
        "null",
        "remove-asset-control",
    )
    text = replace_once(
        text,
        "`${candidates.length} asset${candidates.length === 1 ? '' : 's'} loaded. Only the current page is rendered to keep browser memory bounded; Save and analysis still use the complete bundle. Publicly Exposed remains separate from Internet Facing, and CR/IR/AR remain direct customer CVSS v4 declarations.`",
        "`${candidates.length} asset${candidates.length === 1 ? '' : 's'} loaded. Only the current page is rendered to keep browser memory bounded; Save and analysis still use the complete bundle. Current customer inputs are Asset Criticality and Internet Facing only.`",
        "asset-list-scope",
    )
    text = replace_once(
        text,
        "`${incomplete} asset${incomplete === 1 ? '' : 's'} still need Asset Criticality and/or Internet Facing for the existing customer-context workflow. CISA Publicly Exposed may remain UNKNOWN; CR/IR/AR may remain X.`",
        "`${incomplete} asset${incomplete === 1 ? '' : 's'} still need Asset Criticality and/or Internet Facing before risk calculation.`",
        "validation-message",
    )
    text = replace_once(
        text,
        "const bodIncomplete = values.filter(value => value.publiclyExposed === 'UNKNOWN').length;\n        const suffix = bodIncomplete ? ` ${bodIncomplete} asset${bodIncomplete === 1 ? '' : 's'} remain BOD-incomplete because Publicly Exposed is UNKNOWN.` : '';\n        setStatus(status, `Saved ${values.length} customer asset context record${values.length === 1 ? '' : 's'} for this run.${suffix}`, 'success');",
        "setStatus(status, `Saved ${values.length} customer asset context record${values.length === 1 ? '' : 's'} for this run. Risk inputs are complete when Asset Criticality and Internet Facing are set.`, 'success');",
        "in-memory-save-message",
    )
    text = replace_once(
        text,
        "el('h2', {class: 'panel-title', text: 'Customer Asset Context — CISA BOD + CVSS v4'}),\n        el('p', {class: 'panel-subtitle', text: 'Asset identity comes from the uploaded CSV. CISA Publicly Exposed and organization-specific CVSS Confidentiality, Integrity, and Availability Requirements are declared directly when known.'})",
        "el('h2', {class: 'panel-title', text: 'Customer Asset Context — Risk Inputs'}),\n        el('p', {class: 'panel-subtitle', text: 'Asset identity comes from the uploaded CSV. For the current risk workflow, provide only Asset Criticality and Internet Facing.'})",
        "asset-panel-heading",
    )
    text = replace_once(
        text,
        "callout('Publicly Exposed follows cisa:PE:1.0.0 and remains UNKNOWN until the customer explicitly assesses it. Internet Facing remains separate legacy context and cannot set Publicly Exposed or MAV. CR/IR/AR use FIRST CVSS v4 values X/L/M/H and are not inferred from Asset Criticality.'),",
        "callout('Do not infer these values from the hostname, scanner severity, CVSS, or the number of findings. Asset Criticality and Internet Facing must be customer-declared. Legacy V4 fields remain preserved for replay but are outside the current input scope.'),",
        "asset-panel-callout",
    )
    text = replace_once(
        text,
        "el('div', {class: 'inline-actions'}, uploadButton, addButton, saveButton, downloadButton, enrichedButton, finishButton),",
        "el('div', {class: 'inline-actions'}, uploadButton, saveButton, downloadButton, enrichedButton, finishButton),",
        "asset-toolbar-scope",
    )
    text = replace_once(
        text,
        "saveButton.insertAdjacentElement('afterend', analyzeButton);",
        "analyzeButton.hidden = true;",
        "single-analysis-entry-point",
    )
    text = replace_once(
        text,
        "const bodIncomplete = bundle.assets.filter(asset => asset.publiclyExposed === 'UNKNOWN').length;\n      const suffix = bodIncomplete ? ` ${bodIncomplete} asset${bodIncomplete === 1 ? '' : 's'} remain BOD-incomplete because Publicly Exposed is UNKNOWN.` : '';\n      setStatus(panel, `Saved ${bundle.assets.length} customer asset context record${bundle.assets.length === 1 ? '' : 's'} to the Local API.${suffix}`, 'success');",
        "setStatus(panel, `Saved ${bundle.assets.length} customer asset context record${bundle.assets.length === 1 ? '' : 's'} to the Local API. Current risk inputs are Asset Criticality and Internet Facing.`, 'success');",
        "local-save-message",
    )
    text = replace_once(
        text,
        "summary.textContent = `Analysis ${analysis.analysisId} is immutable. Pareto treatment priority is complete for rankable rows; Organizational Risk remains NON_COMPUTABLE.`;",
        "summary.textContent = `Analysis ${analysis.analysisId} is immutable. Pareto treatment priority is separate; organizational risk is available through the selectable risk methods in Finding Review.`;",
        "analysis-result-summary",
    )
    text = replace_once(
        text,
        "setStatus(panel, 'Saved customer context was analyzed and Pareto treatment priority was materialized. Organizational Risk remains NON_COMPUTABLE.', 'success');",
        "setStatus(panel, 'Saved customer context was analyzed and Pareto treatment priority was materialized. Open Finding Review to choose and calculate one organizational risk method.', 'success');",
        "analysis-result-status",
    )
    text = replace_once(
        text,
        "el('p', {class: 'panel-subtitle', text: `Immutable contextual analysis ${analysisId}. Saved V4 customer context + relative MVP treatment priority; Organizational Risk remains NON_COMPUTABLE.`})",
        "el('p', {class: 'panel-subtitle', text: `Immutable contextual analysis ${analysisId}. Saved customer context + relative MVP treatment priority + explicit selectable organizational risk methods.`})",
        "review-subtitle",
    )
    text = replace_once(
        text,
        "metric('Risk-method admission', admission?.selection?.state || 'UNKNOWN'), metric('Organizational Risk', 'NON_COMPUTABLE')",
        "metric('Risk-method admission', admission?.selection?.state || 'UNKNOWN'), metric('Organizational Risk', 'SELECT METHOD', 'Calculated separately from MVP Priority')",
        "review-risk-metric",
    )

    path.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
