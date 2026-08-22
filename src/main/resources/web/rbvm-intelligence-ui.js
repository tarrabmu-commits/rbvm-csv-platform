(()=>{'use strict';
const CONTRACT='DEDICATED_INTELLIGENCE_PRESENTATION_V1';
const previousFetch=window.fetch.bind(window),byCve=new Map();let queued=false;
document.documentElement.dataset.intelligenceUiContract=CONTRACT;

function remember(item){
  if(!item||typeof item!=='object')return;
  const cve=String(item.cveId||'').trim().toUpperCase();
  if(!/^CVE-\d{4}-\d{4,}$/.test(cve))return;
  const intel=item.vulnerabilityIntelligence;
  if(intel&&typeof intel==='object')byCve.set(cve,intel);
}
function observePayload(payload){
  if(!payload||typeof payload!=='object')return;
  if(Array.isArray(payload.cases))payload.cases.forEach(remember);
  if(payload.cveId)remember(payload);
  schedule();
}
window.fetch=async(input,options)=>{
  const response=await previousFetch(input,options);
  try{
    const url=new URL(typeof input==='string'?input:input.url,location.href);
    if(response.ok&&(url.pathname==='/api/v1/cases'||/^\/api\/v1\/cases\/[a-f0-9]{64}$/.test(url.pathname))){
      response.clone().json().then(observePayload).catch(()=>{});
    }
  }catch(_){}
  return response;
};

function schedule(){if(queued)return;queued=true;queueMicrotask(()=>{queued=false;patch()})}
function cveFor(node){const match=(node?.textContent||'').toUpperCase().match(/CVE-\d{4}-\d{4,}/);return match?.[0]||null}
function state(intel){
  if(!intel)return null;
  if(intel.kevEvidenceState==='AMBIGUOUS')return'AMBIGUOUS';
  if(intel.kevEvidenceState==='MISSING'||intel.kevStatus==='UNKNOWN'||intel.knownExploited==null)return'UNKNOWN';
  if(intel.knownExploited===true||intel.kevStatus==='LISTED')return'LISTED';
  if(intel.knownExploited===false||intel.kevStatus==='NOT_LISTED')return'NOT_LISTED';
  return'UNKNOWN';
}
function label(s){return s==='AMBIGUOUS'?'Ambiguous':s==='UNKNOWN'?'Unknown':s==='LISTED'?'Listed':'Not listed'}
function note(intel,s){
  if(s==='AMBIGUOUS')return`CISA KEV evidence is ambiguous across ${intel.kevSourceCount??'multiple'} current sources; no source precedence was applied.`;
  if(s==='UNKNOWN')return'CISA KEV membership is unknown because no unambiguous current dedicated evidence is available.';
  if(s==='LISTED')return intel.kevObservedAt?`Listed in current CISA KEV evidence observed ${intel.kevObservedAt}.`:'Listed in current CISA KEV evidence.';
  return intel.kevObservedAt?`Not listed in the validated CISA KEV snapshot observed ${intel.kevObservedAt}.`:'Not listed in the validated current CISA KEV snapshot.';
}
function setValue(element,intel){const s=state(intel);if(!s||!element)return;element.textContent=label(s);element.dataset.evidenceState=s;element.title=note(intel,s)}
function patchTables(){
  for(const table of document.querySelectorAll('table')){
    const headers=[...table.querySelectorAll('thead th')].map(x=>(x.textContent||'').trim().toUpperCase());
    const kevIndex=headers.indexOf('KEV');if(kevIndex<0)continue;
    for(const row of table.querySelectorAll('tbody tr')){
      const cve=cveFor(row),intel=cve?byCve.get(cve):null,cells=row.querySelectorAll('td');
      if(intel&&cells.length>kevIndex)setValue(cells[kevIndex],intel);
    }
  }
}
function patchDrawer(){
  const drawer=document.querySelector('.drawer');if(!drawer)return;
  const cve=cveFor(drawer),intel=cve?byCve.get(cve):null;if(!intel)return;
  for(const element of drawer.querySelectorAll('.badge')){
    const text=(element.textContent||'').trim();
    if(['KEV listed','Not listed in KEV','Listed','Not listed','Unknown','Ambiguous'].includes(text)){setValue(element,intel);break}
  }
}
function coverage(predicate){
  const values=[...byCve.values()];
  if(!values.length)return null;
  return Math.round(values.filter(predicate).length*100/values.length);
}
function setMetric(name,value,newLabel=null){
  for(const metric of document.querySelectorAll('.metric')){
    const labelNode=metric.querySelector('.metric-label');
    if((labelNode?.textContent||'').trim()!==name)continue;
    const valueNode=metric.querySelector('.metric-value');if(valueNode)valueNode.textContent=String(value);
    if(newLabel)labelNode.textContent=newLabel;
  }
}
function patchCoverage(){
  if(!byCve.size)return;
  const cvss=coverage(x=>x.cvssEvidenceState==='PRESENT'&&x.cvssBaseScore!=null);
  const epss=coverage(x=>x.epssEvidenceState==='PRESENT'&&x.epssProbability!=null);
  const kev=coverage(x=>x.kevEvidenceState==='PRESENT'&&typeof x.knownExploited==='boolean');
  const listed=[...byCve.values()].filter(x=>x.kevEvidenceState==='PRESENT'&&x.knownExploited===true).length;
  setMetric('Known exploited CVEs',listed);
  setMetric('CVSS available',`${cvss}%`);
  setMetric('EPSS available',`${epss}%`);
  setMetric('CVSS coverage',`${cvss}%`);
  setMetric('EPSS coverage',`${epss}%`);
  setMetric('KEV assessed',`${kev}%`);
  setMetric('Findings evaluated',byCve.size,'CVEs evaluated');
}
function patch(){patchTables();patchDrawer();patchCoverage()}
new MutationObserver(schedule).observe(document.documentElement,{childList:true,subtree:true});
window.addEventListener('DOMContentLoaded',schedule);
})();
