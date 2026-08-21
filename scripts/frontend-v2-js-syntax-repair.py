#!/usr/bin/env python3
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "src/main/resources/web/rbvm-ui.js"
text = path.read_text(encoding="utf-8")
start = "  async function renderReports(){"
end = "\n  async function reportBuilder(template){"
if text.count(start) != 1 or text.count(end) != 1:
    raise SystemExit("renderReports sentinels must each occur exactly once")
before, rest = text.split(start, 1)
_, after = rest.split(end, 1)
replacement = '''  async function renderReports(){
    const root=clear(page());
    root.append(pageHeader('Reports','Generate readable current-state reports without overstating historical or risk semantics.'));
    const templates=[
      ['executive','Executive summary','Management-focused exposure summary.'],
      ['vulnerability','Vulnerability analysis','Technical current-finding analysis.'],
      ['threat','Threat exposure','KEV and EPSS signals.'],
      ['asset','Asset exposure','Asset-centric concentration.'],
      ['readiness','Decision readiness','Current evidence completeness.']
    ];
    const cards=h('div',{class:'grid-3'});
    templates.forEach(([id,name,description])=>{
      cards.append(h(
        'button',
        {class:'panel',type:'button',style:'text-align:left;padding:0',onclick:()=>reportBuilder(id)},
        h('div',{class:'panel-body'},
          h('h2',{class:'panel-title',text:name}),
          h('p',{class:'panel-subtitle',text:description})
        )
      ));
    });
    root.append(
      cards,
      callout('PDF uses the browser print pipeline in this frontend increment. Persistent report definitions, immutable report artifacts, scheduling, and server-side PDF/XLSX generation belong to a report backend increment.')
    );
  }'''
path.write_text(before + replacement + end + after, encoding="utf-8")
print("frontend_v2_js_syntax_repair=APPLIED function=renderReports")
