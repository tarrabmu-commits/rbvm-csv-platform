#!/usr/bin/env python3
"""Evaluate versioned CSV-first risk methods against one immutable analysis CSV."""
from __future__ import annotations
import argparse, csv, hashlib, json, math
from collections import Counter, defaultdict
from pathlib import Path

METHOD_CONTRACT='CSV_FIRST_RISK_METHOD_DEFINITION_V1'
REPORT_CONTRACT='CSV_FIRST_RISK_REPORT_V1'
READINESS_CONTRACT='CSV_FIRST_RISK_READINESS_V1'
OUTPUT_COLUMNS=['Risk_Method_ID','Risk_Method_Version','Risk_Method_SHA256','Risk_Status','Risk_Score','Risk_Scale','Risk_Rating','Risk_Blockers','Risk_Explanation_JSON']
TRUE_VALUES={'true','1','yes','listed'}
FALSE_VALUES={'false','0','no','not_listed','not-listed'}

def arguments():
    p=argparse.ArgumentParser(description=__doc__); sub=p.add_subparsers(dest='command',required=True)
    e=sub.add_parser('evaluate'); e.add_argument('analysis_csv',type=Path); e.add_argument('method_definition',type=Path); e.add_argument('risk_csv',type=Path); e.add_argument('report_json',type=Path)
    r=sub.add_parser('readiness'); r.add_argument('analysis_csv',type=Path); r.add_argument('methods_directory',type=Path); r.add_argument('output_json',type=Path)
    return p.parse_args()

def sha256_file(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()
def canonical_json(v): return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def text(v): return str(v or '').strip()
def load_method(path):
    if not path.is_file() or path.is_symlink(): raise RuntimeError('method definition must be a regular file')
    v=json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(v,dict) or v.get('contractId')!=METHOD_CONTRACT: raise RuntimeError(f'expected {METHOD_CONTRACT}')
    if not v.get('methodId') or int(v.get('methodVersion',0))<1: raise RuntimeError('method definition identity is invalid')
    return v
def read_rows(path):
    if not path.is_file() or path.is_symlink(): raise RuntimeError('analysis CSV must be a regular non-symlink file')
    with path.open('r',encoding='utf-8-sig',newline='') as f:
        rd=csv.DictReader(f); headers=list(rd.fieldnames or [])
        if 'CVE_ID' not in headers: raise RuntimeError('analysis CSV must contain CVE_ID')
        collisions=sorted(set(headers)&set(OUTPUT_COLUMNS))
        if collisions: raise RuntimeError('analysis CSV already contains risk output columns: '+', '.join(collisions))
        rows=list(rd)
    if not rows: raise RuntimeError('analysis CSV must contain at least one finding row')
    return headers,rows
def parse_float(v,minimum=None,maximum=None):
    raw=text(v)
    if not raw:return None
    try:n=float(raw)
    except ValueError:return None
    if not math.isfinite(n) or (minimum is not None and n<minimum) or (maximum is not None and n>maximum):return None
    return n
def resolve_first_numeric(row,cols,minimum,maximum):
    for c in cols:
        n=parse_float(row.get(c),minimum,maximum)
        if n is not None:return n,c
    return None,None
def resolve_bool(v):
    raw=text(v).lower()
    if raw in TRUE_VALUES:return True
    if raw in FALSE_VALUES:return False
    return None
def asset_identity(row):
    for f in ('Agent_ID','Asset_ID'):
        v=text(row.get(f))
        if v:return 'KEY:'+v,f
    for f in ('Agent','Asset_Name','Hostname'):
        v=text(row.get(f))
        if v:return 'NAME:'+v.casefold(),f
    return None,None
def common_context(rows):
    ids=[]; by=defaultdict(set); missing=0
    for row in rows:
        ident,_=asset_identity(row)
        if ident is None: missing+=1; continue
        ids.append(ident); cve=text(row.get('CVE_ID')).upper()
        if cve: by[cve].add(ident)
    return {'distinctAssets':len(set(ids)),'missingAssetIdentityRows':missing,'affectedAssetsByCve':{k:len(v) for k,v in by.items()}}
def rating(score,bands):
    for b in sorted(bands,key=lambda x:float(x['minimum']),reverse=True):
        if score>=float(b['minimum']):return str(b['rating'])
    return ''
def scale_text(method):
    s=method['nativeScale']; return f'{s["minimum"]}..{s["maximum"]}'
def criticality_value(row,method,blockers):
    v=text(row.get('Asset_Criticality')).upper(); m=method.get('policy',{}).get('assetCriticalityMap',{})
    if v not in m: blockers.append('ASSET_CRITICALITY_MISSING_OR_INVALID'); return None
    return float(m[v])
def require_binary(row,column,blocker,blockers):
    v=resolve_bool(row.get(column))
    if v is None:blockers.append(blocker)
    return v
def cvss_value(row,method,blockers):
    cols=method.get('inputs',{}).get('cvssColumns',['CVSS4_Base_Score_Calculated','CVSS4_Base_Score'])
    v,src=resolve_first_numeric(row,cols,0,10)
    if v is None:blockers.append('CVSS_BASE_MISSING_OR_INVALID')
    return v,src
def epss_probability(row,blockers):
    v=parse_float(row.get('EPSS_Probability'),0,1)
    if v is None:blockers.append('EPSS_PROBABILITY_MISSING_OR_INVALID')
    return v
def epss_percentile(row,blockers):
    v=parse_float(row.get('EPSS_Percentile'),0,1)
    if v is None:blockers.append('EPSS_PERCENTILE_MISSING_OR_INVALID')
    return v
def kev_value(row,blockers):
    v=resolve_bool(row.get('KEV_Listed'))
    if v is None:blockers.append('KEV_STATE_MISSING_OR_INVALID')
    return v

def rbvm_common(row,method,exposure_column,exposure_blocker,modifier_key):
    blockers=[]; cvss,src=cvss_value(row,method,blockers); epss=epss_probability(row,blockers); kev=kev_value(row,blockers); asset=criticality_value(row,method,blockers)
    exposure_flag=require_binary(row,exposure_column,exposure_blocker,blockers)
    if blockers:return None,blockers,{'requiredEvidence':'INCOMPLETE'}
    p=method['policy']; impact=math.sqrt(cvss*asset); p0=float(p['epssBaselineProbability']); baseline=p0/(1-p0)
    odds=(epss/(1-epss)) if epss<1 else math.inf
    if kev: z=1.0; resolution='KEV_OVERRIDE'
    elif math.isinf(odds): z=1.0; resolution='EPSS'
    else:
        oratio=odds/baseline; z=(oratio-1)/(oratio+1); resolution='EPSS'
    q=int(p['threatPower']); pos=max(z,0)**q; neg=max(-z,0)**q
    core=impact+float(p['positiveThreatHeadroomAuthority'])*pos*(10-impact)-float(p['negativeThreatDiscountAuthority'])*neg*impact
    modifier=float(p[modifier_key]) if exposure_flag else 0.0; score=min(10,max(0,core+modifier))
    exp={'cvssBase':round(cvss,6),'cvssSourceColumn':src,'assetCriticality':text(row.get('Asset_Criticality')).upper(),'assetCriticalityValue':asset,'impact':round(impact,6),'epssProbability':epss,'epssBaselineProbability':p0,'kevListed':kev,'threatResolution':resolution,'z':round(z,9),'core':round(core,6),exposure_column:exposure_flag,modifier_key:modifier}
    return score,[],exp
def evaluate_rbvm(row,method,_): return rbvm_common(row,method,'Publicly_Exposed','PUBLICLY_EXPOSED_MISSING_OR_INVALID','publicExposureModifier')
def evaluate_rbvm_v2(row,method,_): return rbvm_common(row,method,'Internet_Facing','INTERNET_FACING_MISSING_OR_INVALID','internetFacingModifier')

def jupiter_common(row,method,context,multiplier):
    blockers=[]; cvss,src=cvss_value(row,method,blockers); pct=epss_percentile(row,blockers); ident,ident_src=asset_identity(row)
    if ident is None:blockers.append('CSV_ASSET_IDENTITY_MISSING')
    if context['missingAssetIdentityRows']>0:blockers.append('CSV_ASSET_POPULATION_INCOMPLETE')
    pop=int(context['distinctAssets']); cve=text(row.get('CVE_ID')).upper(); affected=int(context['affectedAssetsByCve'].get(cve,0))
    if pop<1:blockers.append('CSV_ASSET_POPULATION_EMPTY')
    if affected<1:blockers.append('CVE_AFFECTED_ASSET_COUNT_EMPTY')
    if blockers:return None,sorted(set(blockers)),{'requiredEvidence':'INCOMPLETE'}
    p=method['policy']; cvss_c=float(p['cvssWeight'])*(cvss/10)**float(p['cvssExponent']); epss_c=float(p['epssPercentileWeight'])*pct
    ratio=affected/pop; occurrence=min(float(p['occurrenceCap']),ratio*multiplier); score=min(1,max(0,cvss_c+epss_c+occurrence))
    exp={'cvssBase':round(cvss,6),'cvssSourceColumn':src,'cvssComponent':round(cvss_c,9),'epssPercentile':pct,'epssPercentileComponent':round(epss_c,9),'assetIdentitySourceColumn':ident_src,'affectedAssets':affected,'csvDistinctAssets':pop,'populationScope':'DISTINCT_ASSETS_IN_THIS_INPUT_CSV','occurrenceRatio':round(ratio,9),'occurrenceMultiplier':multiplier,'occurrenceCap':float(p['occurrenceCap']),'occurrenceComponent':round(occurrence,9)}
    return score,[],exp
def evaluate_jupiter(row,method,context): return jupiter_common(row,method,context,1.0)
def evaluate_jupiter_v2(row,method,context): return jupiter_common(row,method,context,float(method['policy'].get('occurrenceMultiplier',10.0)))

def evaluate_servicenow(row,method,_):
    blockers=[]; cvss,src=cvss_value(row,method,blockers); epss=epss_probability(row,blockers); asset=criticality_value(row,method,blockers); internet=require_binary(row,'Internet_Facing','INTERNET_FACING_MISSING_OR_INVALID',blockers)
    if blockers:return None,blockers,{'requiredEvidence':'INCOMPLETE'}
    p=method['policy']; w=p['weights']; severity=10*cvss; epssf=100*epss; exposure=100 if internet else 0
    score=(float(w['severity'])*severity+float(w['epss'])*epssf+float(w['criticality'])*asset+float(w['exposure'])*exposure)/100; score=min(100,max(0,score))
    return score,[],{'configurationSemantics':'SERVICENOW_CALCULATOR_STYLE_LOCAL_DEMO_CONFIGURATION','cvssBase':round(cvss,6),'cvssSourceColumn':src,'severityFactor':round(severity,6),'epssProbability':epss,'epssFactor':round(epssf,6),'assetCriticality':text(row.get('Asset_Criticality')).upper(),'criticalityFactor':asset,'internetFacing':internet,'exposureFactor':exposure,'weights':w}
def threshold_factor(value,rules):
    for r in rules:
        lo=r.get('minimum'); hi=r.get('maximum')
        if lo is not None and value<float(lo):continue
        if hi is not None and value>=float(hi):continue
        return float(r['offset']),str(r['label'])
    raise RuntimeError('no factor rule matched')
def evaluate_brinqa(row,method,_):
    blockers=[]; cvss,src=cvss_value(row,method,blockers); epss=epss_probability(row,blockers); kev=kev_value(row,blockers); crit=text(row.get('Asset_Criticality')).upper(); p=method['policy']; offsets=p['assetCriticalityOffsets']
    if crit not in offsets:blockers.append('ASSET_CRITICALITY_MISSING_OR_INVALID')
    internet=require_binary(row,'Internet_Facing','INTERNET_FACING_MISSING_OR_INVALID',blockers)
    if blockers:return None,blockers,{'requiredEvidence':'INCOMPLETE'}
    eo,band=threshold_factor(epss,p['epssOffsets']); ko=float(p['kevListedOffset']) if kev else 0; co=float(offsets[crit]); xo=float(p['internetFacingOffset']) if internet else 0; raw=cvss+eo+ko+co+xo; score=min(10,max(0,raw))
    return score,[],{'configurationSemantics':'BRINQA_RISK_FACTOR_STYLE_LOCAL_BENCHMARK','baseFromCvss':round(cvss,6),'cvssSourceColumn':src,'epssProbability':epss,'epssBand':band,'epssOffset':eo,'kevListed':kev,'kevOffset':ko,'assetCriticality':crit,'assetCriticalityOffset':co,'internetFacing':internet,'internetFacingOffset':xo,'rawBeforeClamp':round(raw,6)}

EVALUATORS={'RBVM_BOUNDED':evaluate_rbvm,'RBVM_BOUNDED_V2':evaluate_rbvm_v2,'JUPITERONE_STYLE':evaluate_jupiter,'JUPITERONE_STYLE_V2':evaluate_jupiter_v2,'SERVICENOW_STYLE':evaluate_servicenow,'BRINQA_STYLE':evaluate_brinqa}
def evaluate_row(row,method,context):
    fn=EVALUATORS.get(str(method.get('implementation') or ''))
    if fn is None:raise RuntimeError('unsupported method implementation: '+str(method.get('implementation')))
    return fn(row,method,context)
def readiness_for(rows,method,context):
    blockers=Counter(); computable=0
    for row in rows:
        score,bs,_=evaluate_row(row,method,context)
        if score is not None and not bs:computable+=1
        else:blockers.update(bs)
    return {'methodId':method['methodId'],'methodVersion':method['methodVersion'],'computableRows':computable,'nonComputableRows':len(rows)-computable,'blockers':dict(sorted(blockers.items()))}

def run_evaluate(a):
    method=load_method(a.method_definition); headers,rows=read_rows(a.analysis_csv); context=common_context(rows); msha=sha256_file(a.method_definition); ssha=sha256_file(a.analysis_csv)
    computed=non=0; bc=Counter(); scores=[]; ratings=Counter(); a.risk_csv.parent.mkdir(parents=True,exist_ok=True)
    with a.risk_csv.open('w',encoding='utf-8',newline='') as f:
        wr=csv.DictWriter(f,fieldnames=headers+OUTPUT_COLUMNS); wr.writeheader()
        for row in rows:
            score,blockers,explanation=evaluate_row(row,method,context); joined=dict(row)
            if score is None or blockers:
                non+=1; bc.update(blockers); joined.update({'Risk_Method_ID':method['methodId'],'Risk_Method_Version':str(method['methodVersion']),'Risk_Method_SHA256':msha,'Risk_Status':'NON_COMPUTABLE','Risk_Score':'','Risk_Scale':scale_text(method),'Risk_Rating':'','Risk_Blockers':'|'.join(sorted(set(blockers))),'Risk_Explanation_JSON':canonical_json(explanation)})
            else:
                computed+=1; scores.append(score); r=rating(score,method.get('ratingBands',[])); ratings.update([r] if r else []); joined.update({'Risk_Method_ID':method['methodId'],'Risk_Method_Version':str(method['methodVersion']),'Risk_Method_SHA256':msha,'Risk_Status':'COMPUTED','Risk_Score':f'{score:.6f}'.rstrip('0').rstrip('.'),'Risk_Scale':scale_text(method),'Risk_Rating':r,'Risk_Blockers':'','Risk_Explanation_JSON':canonical_json(explanation)})
            wr.writerow(joined)
    report={'contractId':REPORT_CONTRACT,'methodId':method['methodId'],'methodVersion':method['methodVersion'],'methodSha256':msha,'classification':method['classification'],'provider':method.get('provider'),'nativeScale':method['nativeScale'],'sourceAnalysisCsv':a.analysis_csv.name,'sourceAnalysisSha256':ssha,'riskCsv':a.risk_csv.name,'riskCsvSha256':sha256_file(a.risk_csv),'scope':{'findingRows':len(rows),'uniqueCves':len({text(r.get('CVE_ID')).upper() for r in rows if text(r.get('CVE_ID'))}),'distinctAssets':context['distinctAssets'],'missingAssetIdentityRows':context['missingAssetIdentityRows']},'result':{'computedRows':computed,'nonComputableRows':non,'blockers':dict(sorted(bc.items())),'ratingCounts':dict(sorted(ratings.items())),'minimumScore':round(min(scores),9) if scores else None,'maximumScore':round(max(scores),9) if scores else None,'meanScore':round(sum(scores)/len(scores),9) if scores else None},'methodSemantics':method.get('semantics'),'immutableInput':True,'networkIoUsed':False,'databaseStateUsed':False}
    a.report_json.parent.mkdir(parents=True,exist_ok=True); a.report_json.write_text(json.dumps(report,indent=2,sort_keys=True,ensure_ascii=False)+'\n',encoding='utf-8'); print(json.dumps(report,sort_keys=True))
def run_readiness(a):
    _,rows=read_rows(a.analysis_csv); context=common_context(rows); methods=[]
    for path in sorted(a.methods_directory.glob('*.json')):
        if path.is_symlink() or not path.is_file():continue
        m=load_method(path); v=readiness_for(rows,m,context); v.update({'methodSha256':sha256_file(path),'classification':m['classification'],'provider':m.get('provider'),'nativeScale':m['nativeScale']}); methods.append(v)
    report={'contractId':READINESS_CONTRACT,'sourceAnalysisSha256':sha256_file(a.analysis_csv),'scope':{'findingRows':len(rows),'distinctAssets':context['distinctAssets'],'missingAssetIdentityRows':context['missingAssetIdentityRows']},'methods':methods}; a.output_json.write_text(json.dumps(report,indent=2,sort_keys=True,ensure_ascii=False)+'\n',encoding='utf-8'); print(json.dumps(report,sort_keys=True))
def main():
    a=arguments(); run_evaluate(a) if a.command=='evaluate' else run_readiness(a)
if __name__=='__main__':main()
