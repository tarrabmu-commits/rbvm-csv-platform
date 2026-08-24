#!/usr/bin/env python3
"""Fail-closed compile-time integration for canonical MVP priority UI.

This edits only the built dependency-free frontend artifact. It does not add a
MutationObserver overlay and does not implement any priority math in the browser.
"""

from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: integrate-canonical-mvp-priority-ui.py <rbvm-ui.js>")

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")


def replace_once(old, new, label):
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"canonical MVP priority UI integration drift: {label} matched {count} times")
    text = text.replace(old, new, 1)


replace_once(
    """  function announceCompleted(data) {\n    document.documentElement.dataset.canonicalImportId = data.importId;""",
    """  function announceCompleted(data) {\n    document.documentElement.dataset.canonicalImportId = data.importId;\n    const currentUrl = new URL(location.href);\n    currentUrl.searchParams.set('canonicalImportId', data.importId);\n    history.replaceState(history.state, '', currentUrl);""",
    "persist canonical import identity in route",
)

replace_once(
    """    const downloadBundle = artifactButton('Download exact customer bundle', run.customerBundle, `rbvm-customer-bundle-${runId}-${analysisId}.json`, 'ghost');\n    const close = button('Back to Assets', 'ghost');""",
    """    const downloadBundle = artifactButton('Download exact customer bundle', run.customerBundle, `rbvm-customer-bundle-${runId}-${analysisId}.json`, 'ghost');\n    const canonicalImportId = new URLSearchParams(location.search).get('canonicalImportId') || document.documentElement.dataset.canonicalImportId || '';\n    const persistCanonicalPriority = button(canonicalImportId ? 'Persist to canonical Findings' : 'Canonical import required', 'secondary');\n    persistCanonicalPriority.disabled = !canonicalImportId;\n    persistCanonicalPriority.addEventListener('click', async () => {\n      if (!canonicalImportId) return;\n      persistCanonicalPriority.disabled = true;\n      const previous = persistCanonicalPriority.textContent;\n      persistCanonicalPriority.textContent = 'Persisting canonical priority…';\n      try {\n        const response = await api(`/api/v1/canonical-mvp-priorities/${encodeURIComponent(canonicalImportId)}/${encodeURIComponent(runId)}/${encodeURIComponent(analysisId)}`, {method: 'POST'});\n        const data = await response.json();\n        persistCanonicalPriority.textContent = `Canonical priority persisted · ${data.canonicalFindings ?? 0} Findings`;\n        persistCanonicalPriority.title = `Exact source-row lineage · inserted ${data.insertedResults ?? 0}, replayed ${data.replayedResults ?? 0}`;\n      } catch (error) {\n        persistCanonicalPriority.disabled = false;\n        persistCanonicalPriority.textContent = previous;\n        window.alert(`Canonical priority was not persisted: ${error.message}`);\n      }\n    });\n    const close = button('Back to Assets', 'ghost');""",
    "canonical materialization action",
)

replace_once(
    """downloadPriority, downloadPriorityReport, downloadAnalysis, downloadAdmission, downloadBundle, close""",
    """downloadPriority, downloadPriorityReport, downloadAnalysis, downloadAdmission, downloadBundle, persistCanonicalPriority, close""",
    "run review canonical action placement",
)

replace_once(
    """  async function openFinding(item){const body=drawer(item.cveId,item.assetName);body.append(loading());try{const detail=await json(`/api/v1/cases/${encodeURIComponent(item.caseId)}`);renderFinding(body,detail,'overview');}catch(error){body.replaceChildren(failure(error,()=>openFinding(item)));}}""",
    """  async function canonicalMvpPriorityForDetail(detail){const exposures=detail.exposures||[];if(!exposures.length)return detail;const enriched=await Promise.all(exposures.map(async exposure=>{const findingId=exposure.findingId||exposure.exposureId;if(!findingId)return exposure;try{const priority=await json(`/api/v1/canonical-mvp-priorities/findings/${encodeURIComponent(findingId)}`);return {...exposure,canonicalMvpPriority:priority};}catch(error){if(error.status===404||error.status===503)return {...exposure,canonicalMvpPriority:null};throw error;}}));return {...detail,exposures:enriched};}\n  async function openFinding(item){const body=drawer(item.cveId,item.assetName);body.append(loading());try{const detail=await json(`/api/v1/cases/${encodeURIComponent(item.caseId)}`);const enriched=await canonicalMvpPriorityForDetail(detail);renderFinding(body,enriched,'overview');}catch(error){body.replaceChildren(failure(error,()=>openFinding(item)));}}""",
    "lazy canonical priority read",
)

replace_once(
    """['overview','evidence','asset','timeline']""",
    """['overview','priority','evidence','asset','timeline']""",
    "Finding drawer priority tab",
)

replace_once(
    """    } else if(tabName==='evidence'){findingEvidence(body,detail);} else if(tabName==='asset'){""",
    """    } else if(tabName==='priority'){const rows=(detail.exposures||[]).filter(row=>row.canonicalMvpPriority);body.append(panel('Canonical MVP treatment priority','Latest explicitly materialized result for each exact Finding. Relative Pareto priority only; not Organizational Risk or SLA.',rows.length?table([{label:'Product',key:'product'},{label:'Priority',render:r=>{const p=r.canonicalMvpPriority;return p.status==='RANKED_RELATIVE_ONLY'&&p.front?`Front ${p.front}`:'Unrankable';}},{label:'KEV',render:r=>r.canonicalMvpPriority.inputs?.kevListed===true?'LISTED':r.canonicalMvpPriority.inputs?.kevListed===false?'NOT LISTED':'—'},{label:'Internet',render:r=>r.canonicalMvpPriority.inputs?.internetFacing||'—'},{label:'Criticality',render:r=>r.canonicalMvpPriority.inputs?.assetCriticality||'—'},{label:'EPSS',render:r=>r.canonicalMvpPriority.inputs?.epssProbability==null?'—':pct(r.canonicalMvpPriority.inputs.epssProbability,1)},{label:'Context CVSS v4',render:r=>r.canonicalMvpPriority.inputs?.contextualCvssV4??'—'},{label:'Why',render:r=>h('span',{title:r.canonicalMvpPriority.explanation,text:r.canonicalMvpPriority.explanation})}],rows,'Canonical Finding MVP priority'):empty('Canonical priority not materialized','Persist the immutable CSV-run priority onto the exact canonical import before expecting a Finding-level priority here.')));} else if(tabName==='evidence'){findingEvidence(body,detail);} else if(tabName==='asset'){""",
    "Finding priority presentation",
)

path.write_text(text, encoding="utf-8")
print("Canonical MVP priority UI integration: PASS")
