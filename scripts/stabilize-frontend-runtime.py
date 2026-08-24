#!/usr/bin/env python3
"""Apply bounded/retention-safe transforms to the dependency-free frontend runtime.

These are intentionally narrow, fail-closed build transforms while Frontend System V2 is
being consolidated. The stabilized Dashboard must not crawl the full catalog, large managed
asset tables must render one bounded page, and temporary full-catalog arrays must not stay
retained after SPA navigation.
"""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: stabilize-frontend-runtime.py <compiled-rbvm-ui.js>")

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")


def replace_once(old, new, label):
    global text
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"frontend stabilization drift: {label} matched {count} times")
    text = text.replace(old, new, 1)


replace_once(
    "const [sum,cases]=await Promise.all([summary(),allCases()]);",
    "const [sum,cases]=await Promise.all([summary(),json('/api/v1/cases?limit=100').then(data=>data.cases||[])]);",
    "legacy Overview full-catalog read",
)

# Full-catalog arrays are useful while Analytics/Reports/Managed Assets are actively open,
# but keeping them in the global state after leaving the route prevents browser GC. Release
# those arrays at every SPA navigation boundary; API evidence/state is never changed.
replace_once(
    """  function navigate(path, params = null, replace = false) {\n    history[replace ? 'replaceState' : 'pushState']({}, '', url(path, params));\n    closeOverlay(); closeNav(); render();\n  }""",
    """  function navigate(path, params = null, replace = false) {\n    history[replace ? 'replaceState' : 'pushState']({}, '', url(path, params));\n    state.cases = []; state.assets = []; state.reportCases = null;\n    closeOverlay(); closeNav(); render();\n  }""",
    "SPA navigation cache release",
)

replace_once(
    "window.addEventListener('popstate',()=>{closeOverlay();render();});",
    "window.addEventListener('popstate',()=>{state.cases=[];state.assets=[];state.reportCases=null;closeOverlay();render();});",
    "history navigation cache release",
)

# The managed-asset registry may legitimately contain thousands of records. Keep the complete
# list available to search while this route is open, but never instantiate thousands of table
# rows/cells at once. Rendering remains bounded by the existing PAGE_SIZE (100).
replace_once(
    """const tableHolder=h('div');const paint=()=>{const q=search.value.trim().toLowerCase();const rows=assets.filter(a=>!q||[a.currentRevision?.displayName,a.customerAssetKey,a.currentRevision?.businessService,a.currentRevision?.businessOwner].some(v=>String(v||'').toLowerCase().includes(q)));tableHolder.replaceChildren(rows.length?table([{label:'Asset',render:r=>h('strong',{text:r.currentRevision?.displayName||r.id})},{label:'Service',render:r=>r.currentRevision?.businessService||'—'},{label:'Environment',render:r=>title(r.currentRevision?.environment)},{label:'Criticality',render:r=>title(r.currentRevision?.businessCriticality)},{label:'Owner',render:r=>r.currentRevision?.businessOwner||'—'},{label:'Revision',render:r=>r.currentRevision?.revision??'—'}],rows,'Managed assets',openAsset):empty('No assets match','Try a broader search.'));};search.addEventListener('input',paint);paint();""",
    """const tableHolder=h('div');const previousPage=button('Previous',{kind:'ghost'});const nextPage=button('Next',{kind:'ghost'});const pageLabel=h('span');let assetPage=0;const paint=()=>{const q=search.value.trim().toLowerCase();const filtered=assets.filter(a=>!q||[a.currentRevision?.displayName,a.customerAssetKey,a.currentRevision?.businessService,a.currentRevision?.businessOwner].some(v=>String(v||'').toLowerCase().includes(q)));const pages=Math.max(1,Math.ceil(filtered.length/PAGE_SIZE));assetPage=Math.min(assetPage,pages-1);const rows=filtered.slice(assetPage*PAGE_SIZE,assetPage*PAGE_SIZE+PAGE_SIZE);previousPage.disabled=assetPage<=0;nextPage.disabled=assetPage+1>=pages;pageLabel.textContent=`${filtered.length} matching · page ${assetPage+1} of ${pages}`;tableHolder.replaceChildren(filtered.length?table([{label:'Asset',render:r=>h('strong',{text:r.currentRevision?.displayName||r.id})},{label:'Service',render:r=>r.currentRevision?.businessService||'—'},{label:'Environment',render:r=>title(r.currentRevision?.environment)},{label:'Criticality',render:r=>title(r.currentRevision?.businessCriticality)},{label:'Owner',render:r=>r.currentRevision?.businessOwner||'—'},{label:'Revision',render:r=>r.currentRevision?.revision??'—'}],rows,'Managed assets',openAsset):empty('No assets match','Try a broader search.'),h('div',{class:'pagination'},previousPage,pageLabel,nextPage));};search.addEventListener('input',()=>{assetPage=0;paint();});previousPage.addEventListener('click',()=>{if(assetPage>0){assetPage--;paint();}});nextPage.addEventListener('click',()=>{assetPage++;paint();});paint();""",
    "managed asset table pagination",
)

path.write_text(text, encoding="utf-8")
print("Frontend stabilization transform: PASS (bounded Overview/assets DOM + navigation cache release)")
