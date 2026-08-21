#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {text.count(old)}")
    return text.replace(old, new)


def replace_between(text: str, start: str, end: str, replacement: str, label: str) -> str:
    if text.count(start) != 1 or text.count(end) != 1:
        raise SystemExit(f"{label}: sentinels must each occur exactly once")
    before, rest = text.split(start, 1)
    _, after = rest.split(end, 1)
    return before + replacement + end + after


root = Path(__file__).resolve().parents[1]

# V2 SPA HTTP smoke: static hosts no longer contain page-specific copy.
test_path = root / "src/test/java/io/rbvm/csv/CsvHttpSelfTest.java"
test = test_path.read_text(encoding="utf-8")
test_start = '                HttpResponse<String> page = get(client, base.resolve("/"));'
test_end = '\n\n                HttpResponse<String> health = get(client, base.resolve("/api/v1/health"));'
test_replacement = '''                HttpResponse<String> page = get(client, base.resolve("/"));
                assert page.statusCode() == 200;
                assert page.body().contains("<html lang=\\\"en\\\" dir=\\\"ltr\\\">");
                assert page.body().contains("id=\\\"rbvm-app\\\"");
                assert page.body().contains("/ui/rbvm-ui.js");

                HttpResponse<String> assetsPage = get(client, base.resolve("/assets"));
                assert assetsPage.statusCode() == 200;
                assert assetsPage.body().contains("<html lang=\\\"en\\\" dir=\\\"ltr\\\">");
                assert assetsPage.body().contains("id=\\\"rbvm-app\\\"");
                assert assetsPage.body().contains("/ui/rbvm-ui.js");'''
test_path.write_text(
    replace_between(test, test_start, test_end, test_replacement, "CsvHttpSelfTest V2 host smoke"),
    encoding="utf-8",
)

# Repair the V2 navigation syntax and restore guided classification provenance.
js_path = root / "src/main/resources/web/rbvm-ui.js"
js = js_path.read_text(encoding="utf-8")
nav_old = "      items.forEach(([path, labelText, icon]) => list.append(h('li', {}, h('a', {class: 'nav-link', href: url(path), 'data-spa': 'true', 'data-route': path}, h('span', {class: 'nav-icon', text: icon}), h('span', {text: labelText}))));"
nav_new = """      items.forEach(([path, labelText, icon]) => {
        list.append(h(
          'li', {},
          h('a', {class: 'nav-link', href: url(path), 'data-spa': 'true', 'data-route': path},
            h('span', {class: 'nav-icon', text: icon}),
            h('span', {text: labelText}))
        ));
      });"""
js = replace_once(js, nav_old, nav_new, "V2 navigation syntax")

model_start = "  function assetModel(initial={},withLifecycle=false){"
model_end = "\n  function createAsset(){"
model = r'''  function assetModel(initial={},withLifecycle=false){
    const display=field('Display name');display.input.value=initial.displayName||'';
    const service=field('Business service');service.input.value=initial.businessService||'';
    const owner=field('Business owner');owner.input.value=initial.businessOwner||'';
    const env=choice('Environment',['PRODUCTION','PRE_PRODUCTION','DEVELOPMENT','TEST','SANDBOX','DISASTER_RECOVERY','UNKNOWN']);env.input.value=initial.environment||'UNKNOWN';
    const crit=choice('Business criticality',['MISSION_CRITICAL','HIGH','MODERATE','LOW','UNKNOWN']);crit.input.value=initial.businessCriticality||'UNKNOWN';
    const method=choice('Classification method',['CUSTOMER_DIRECT','GUIDED']);method.input.value=initial.classificationMethod||'CUSTOMER_DIRECT';
    const guideId=field('Guide contract ID','ASSET_CLASSIFICATION_GUIDE_V1');guideId.input.value=initial.guideContractId||'ASSET_CLASSIFICATION_GUIDE_V1';
    const guideRevision=field('Guide revision','1','number');guideRevision.input.value=initial.guideRevision??1;guideRevision.input.min='1';guideRevision.input.step='1';
    const guide=h('div',{class:'wide'},callout('Guided classification records explicit guide provenance. It never derives criticality from CVSS, KEV, EPSS, or a hidden score.'),h('div',{class:'form-grid',style:'margin-top:12px'},guideId.wrap,guideRevision.wrap));
    const syncGuide=()=>{const guided=method.input.value==='GUIDED';guide.classList.toggle('hidden',!guided);guideId.input.required=guided;guideRevision.input.required=guided;};method.input.addEventListener('change',syncGuide);syncGuide();
    const note=textarea('Change note');
    const lifecycle=withLifecycle?choice('Lifecycle status',['ACTIVE','RETIRED']):null;if(lifecycle)lifecycle.input.value=initial.lifecycleStatus||'ACTIVE';
    return {grid:h('div',{class:'form-grid'},lifecycle?lifecycle.wrap:null,display.wrap,env.wrap,crit.wrap,service.wrap,owner.wrap,method.wrap,guide,note.wrap),read:()=>{const payload={...(lifecycle?{lifecycleStatus:lifecycle.input.value}:{}),displayName:display.input.value.trim(),environment:env.input.value,businessService:service.input.value.trim(),businessOwner:owner.input.value.trim(),businessCriticality:crit.input.value,classificationMethod:method.input.value,changeNote:note.input.value.trim()};if(method.input.value==='GUIDED'){payload.guideContractId=guideId.input.value.trim();payload.guideRevision=Number(guideRevision.input.value);}return payload;}};
  }'''
js_path.write_text(
    replace_between(js, model_start, model_end, model, "managed asset guided classification"),
    encoding="utf-8",
)

verifier_path = root / "scripts/verify-managed-assets-ui.py"
verifier = verifier_path.read_text(encoding="utf-8")
old = '"customerAssetKey","businessCriticality","classificationMethod"):'
new = '"customerAssetKey","businessCriticality","classificationMethod","guideContractId","guideRevision","ASSET_CLASSIFICATION_GUIDE_V1"):'
verifier_path.write_text(
    replace_once(verifier, old, new, "managed asset provenance verifier"),
    encoding="utf-8",
)

print("frontend_v2_repair=APPLIED")
