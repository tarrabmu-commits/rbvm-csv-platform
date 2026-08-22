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
    if(response.ok&&(/^\/api\/v1\/cases(?:\?|$)/.test(url.pathname+url.search)||/^\/api\/v1\/cases\/[a-f0-9]{64}$/.test(url.pathname))){
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
function note(intel,s){
  if(s==='AMBIGUOUS')return`CISA KEV evidence is ambiguous across ${intel.kevSourceCount??'multiple'} current sources; no source precedence was applied.`;
  if(s==='UNKNOWN')return'CISA KEV membership is unknown because no unambiguous current dedicated evidence is available.';
  if(s==='LISTED')return intel.kevObservedAt?`Listed in current CISA KEV evidence observed ${intel.kevObservedAt}.`:'Listed in current CISA KEV evidence.';
  return intel.kevObservedAt?`Not listed in the validated CISA KEV snapshot observed ${intel.kevObservedAt}.`:'Not listed in the validated current CISA KEV snapshot.';
}
function replacement(s){return s==='AMBIGUOUS'?'Ambiguous':s==='UNKNOWN'?'Unknown':s==='LISTED'?'Listed':'Not listed'}
function patchNode(node,intel){
  const s=state(intel);if(!s)return;
  const expected=replacement(s);
  for(const element of node.querySelectorAll('td,dd,.badge')){
    const text=(element.textContent||'').trim();
    if(text==='Not listed'||text==='Not listed in KEV'||text==='Listed'||text==='KEV listed'||text==='Unknown'||text==='Ambiguous'){
      if((text.includes('listed')||text.includes('Listed')||text==='Unknown'||text==='Ambiguous')&&element.closest('tr,dl,.drawer')){
        element.textContent=expected;
        element.dataset.evidenceState=s;
        element.title=note(intel,s);
      }
    }
  }
}
function patch(){
  for(const row of document.querySelectorAll('tr')){const cve=cveFor(row);if(cve&&byCve.has(cve))patchNode(row,byCve.get(cve))}
  const drawer=document.querySelector('.drawer');if(drawer){const cve=cveFor(drawer);if(cve&&byCve.has(cve))patchNode(drawer,byCve.get(cve))}
}
new MutationObserver(schedule).observe(document.documentElement,{childList:true,subtree:true});
window.addEventListener('DOMContentLoaded',schedule);
})();
