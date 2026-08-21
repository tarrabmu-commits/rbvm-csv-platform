#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def write(path, text):
    (ROOT / path).write_text(text, encoding="utf-8")


def exact(path, old, new, count=1):
    text = read(path)
    actual = text.count(old)
    if actual != count:
        raise AssertionError(f"{path}: expected {count} occurrence(s), found {actual}: {old[:100]!r}")
    write(path, text.replace(old, new, count))


def version_alignment():
    exact("build.gradle.kts", 'version = "0.23.0-SNAPSHOT"', 'version = "0.23.1-SNAPSHOT"')
    exact("api/openapi.yaml", "  version: 0.23.0\n", "  version: 0.23.1\n")
    exact("scripts/build-distribution.sh", "VERSION=0.23.0", "VERSION=0.23.1")
    exact("scripts/verify-reproducible-build.sh", "VERSION=0.23.0", "VERSION=0.23.1")
    exact(
        "scripts/verify-reproducible-build.sh",
        "Implementation-Version: 0.23.0",
        "Implementation-Version: 0.23.1",
    )
    exact(
        "scripts/verify-api.py",
        'document.get("info", {}).get("version") != "0.23.0"',
        'document.get("info", {}).get("version") != "0.23.1"',
    )
    exact(
        "scripts/verify-api.py",
        "OpenAPI info.version must match Increment 23",
        "OpenAPI info.version must match the pre-V24 hardening release 0.23.1",
    )
    for path in (".github/workflows/verify.yml", ".github/workflows/release.yml"):
        text = read(path)
        if "0.23.0" not in text:
            raise AssertionError(f"{path}: expected 0.23.0 release references")
        write(path, text.replace("0.23.0", "0.23.1"))


def managed_assets_ui():
    path = "src/main/resources/web/assets.html"
    text = read(path)

    if text.count(".hidden { display:none !important; }") != 1:
        raise AssertionError("assets UI hidden class anchor mismatch")
    text = text.replace(
        ".hidden { display:none !important; }",
        ".hidden { display:none !important; }\n"
        "    .sr-only { position:absolute; width:1px; height:1px; padding:0; margin:-1px; "
        "overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; border:0; }",
        1,
    )
    old_caption = '<caption class="hidden">Managed asset current-state list</caption>'
    if text.count(old_caption) != 1:
        raise AssertionError("managed asset caption anchor mismatch")
    text = text.replace(
        old_caption,
        '<caption class="sr-only">Managed asset current-state list</caption>',
        1,
    )

    environment = """          <select name="environment" required>\n            <option>PRODUCTION</option><option>PRE_PRODUCTION</option><option>DEVELOPMENT</option><option>TEST</option><option>SANDBOX</option><option>DISASTER_RECOVERY</option><option>UNKNOWN</option>\n          </select>"""
    if text.count(environment) != 2:
        raise AssertionError("expected create+revise environment selects")
    create_environment = """          <select name="environment" required>\n            <option value="" selected disabled>اختر Environment صراحةً</option>\n            <option>PRODUCTION</option><option>PRE_PRODUCTION</option><option>DEVELOPMENT</option><option>TEST</option><option>SANDBOX</option><option>DISASTER_RECOVERY</option><option>UNKNOWN</option>\n          </select>"""
    text = text.replace(environment, create_environment, 1)

    criticality = """          <select name="businessCriticality" required>\n            <option>MISSION_CRITICAL</option><option>HIGH</option><option>MODERATE</option><option>LOW</option><option>UNKNOWN</option>\n          </select>"""
    if text.count(criticality) != 2:
        raise AssertionError("expected create+revise criticality selects")
    create_criticality = """          <select name="businessCriticality" required>\n            <option value="" selected disabled>اختر Business Criticality صراحةً</option>\n            <option>MISSION_CRITICAL</option><option>HIGH</option><option>MODERATE</option><option>LOW</option><option>UNKNOWN</option>\n          </select>"""
    text = text.replace(criticality, create_criticality, 1)

    classification = """          <select name="classificationMethod" class="classificationMethod" required>\n            <option value="CUSTOMER_DIRECT">CUSTOMER_DIRECT</option>\n            <option value="GUIDED">GUIDED</option>\n          </select>"""
    if text.count(classification) != 2:
        raise AssertionError("expected create+revise classification selects")
    create_classification = """          <select name="classificationMethod" class="classificationMethod" required>\n            <option value="" selected disabled>اختر Classification Method صراحةً</option>\n            <option value="CUSTOMER_DIRECT">CUSTOMER_DIRECT</option>\n            <option value="GUIDED">GUIDED</option>\n          </select>"""
    text = text.replace(classification, create_classification, 1)

    if text.count('type="number" min="1"') != 2:
        raise AssertionError("guideRevision numeric anchors changed")
    text = text.replace('type="number" min="1"', 'type="number" min="1" step="1"')

    maxlengths = re.findall(r'\smaxlength="[0-9]+"', text)
    if len(maxlengths) != 11:
        raise AssertionError(f"expected 11 arbitrary maxlength attributes, found {len(maxlengths)}")
    text = re.sub(r'\smaxlength="[0-9]+"', '', text)

    state_anchor = "  let nextBeforeRevision = null;\n"
    if text.count(state_anchor) != 1:
        raise AssertionError("revise-dialog state anchor mismatch")
    text = text.replace(state_anchor, state_anchor + "  let reopenDetailAfterRevise = false;\n", 1)

    open_revise_old = """  function openReviseDialog() {\n    if (!selectedAsset || !selectedEtag || !writeEnabled) return;\n    const revision = selectedAsset.currentRevision;"""
    open_revise_new = """  function openReviseDialog() {\n    if (!selectedAsset || !selectedEtag || !writeEnabled) return;\n    if (byId('detailDialog').open) {\n      byId('detailDialog').close();\n      reopenDetailAfterRevise = true;\n    }\n    const revision = selectedAsset.currentRevision;"""
    if text.count(open_revise_old) != 1:
        raise AssertionError("openReviseDialog anchor mismatch")
    text = text.replace(open_revise_old, open_revise_new, 1)

    revise_success_old = """      selectedAsset = asset;\n      selectedEtag = etag;\n      renderDetail(asset);\n      setStatus('reviseMessage', `تم اعتماد revision ${asset.currentRevision.revision}.`, false, true);\n      byId('reviseDialog').close();\n      nextBeforeRevision = null;\n      await loadHistory(false);\n      await loadAssets();\n      setStatus('detailMessage', `Current revision ${asset.currentRevision.revision}.`, false, true);"""
    revise_success_new = """      selectedAsset = asset;\n      selectedEtag = etag;\n      const detailId = selectedAssetId;\n      setStatus('reviseMessage', `تم اعتماد revision ${asset.currentRevision.revision}.`, false, true);\n      reopenDetailAfterRevise = false;\n      byId('reviseDialog').close();\n      await loadAssets();\n      await openDetail(detailId);"""
    if text.count(revise_success_old) != 1:
        raise AssertionError("revise success anchor mismatch")
    text = text.replace(revise_success_old, revise_success_new, 1)

    close_anchor = """  byId('olderHistory').addEventListener('click', () => loadHistory(true));\n\n  if (apiToken) {"""
    close_new = """  byId('olderHistory').addEventListener('click', () => loadHistory(true));\n  byId('reviseDialog').addEventListener('close', () => {\n    if (!reopenDetailAfterRevise || !selectedAssetId) return;\n    const detailId = selectedAssetId;\n    reopenDetailAfterRevise = false;\n    openDetail(detailId).catch(error =>\n      setStatus('healthMessage', error.message || 'تعذر إعادة فتح تفاصيل managed asset.', true));\n  });\n\n  if (apiToken) {"""
    if text.count(close_anchor) != 1:
        raise AssertionError("revise close-event anchor mismatch")
    text = text.replace(close_anchor, close_new, 1)

    write(path, text)


def managed_assets_ui_verifier():
    path = "scripts/verify-managed-assets-ui.py"
    text = read(path)
    require_anchor = """        'textContent',\n    ):"""
    require_new = """        'textContent',\n        '<caption class="sr-only">Managed asset current-state list</caption>',\n        '<option value="" selected disabled>اختر Environment صراحةً</option>',\n        '<option value="" selected disabled>اختر Business Criticality صراحةً</option>',\n        '<option value="" selected disabled>اختر Classification Method صراحةً</option>',\n        'type="number" min="1" step="1"',\n        "byId('detailDialog').close();",\n        'reopenDetailAfterRevise',\n    ):"""
    if text.count(require_anchor) != 1:
        raise AssertionError("managed assets verifier require anchor mismatch")
    text = text.replace(require_anchor, require_new, 1)
    forbid_anchor = """        'document.write',\n    ):"""
    forbid_new = """        'document.write',\n        '<caption class="hidden">Managed asset current-state list</caption>',\n        'maxlength=',\n    ):"""
    if text.count(forbid_anchor) != 1:
        raise AssertionError("managed assets verifier forbid anchor mismatch")
    text = text.replace(forbid_anchor, forbid_new, 1)
    write(path, text)


def readme():
    path = "README.md"
    text = read(path)
    text = text.replace("OpenAPI 0.23.0", "OpenAPI 0.23.1")
    text = text.replace("rbvm-csv-platform-0.23.0", "rbvm-csv-platform-0.23.1")
    text = text.replace("v0.23.0", "v0.23.1")

    old_runtime = """تشغيل الخادم يحتاج JDK 17 أوأحدث فقط ولا توجد مكتبات runtime خارجية. حزمة التحقق\nللمطور تحتاج أيضاً Python 3 وPyYAML لتدقيق OpenAPI وSQL."""
    new_runtime = """الوضع المحلي من الـJAR يحتاج JDK 17 أوأحدث فقط. عند تفعيل PostgreSQL يحتاج التشغيل أيضاً\npgJDBC خارج حزمة التطبيق على الـclasspath؛ حزمة التحقق للمطور تحتاج Python 3 وPyYAML\nلتدقيق OpenAPI وSQL."""
    if text.count(old_runtime) != 1:
        raise AssertionError("README local runtime dependency wording anchor mismatch")
    text = text.replace(old_runtime, new_runtime, 1)

    migration_anchor = "- [`db/migration/V15__business_impact_persistence.sql`](db/migration/V15__business_impact_persistence.sql)\n"
    migration_extra = migration_anchor + """- [`db/migration/V16__decision_methodology_policy_persistence.sql`](db/migration/V16__decision_methodology_policy_persistence.sql)\n- [`db/migration/V17__decision_input_snapshot_persistence.sql`](db/migration/V17__decision_input_snapshot_persistence.sql)\n- [`db/migration/V18__managed_asset_registry.sql`](db/migration/V18__managed_asset_registry.sql)\n- [`db/migration/V19__scanner_managed_asset_link.sql`](db/migration/V19__scanner_managed_asset_link.sql)\n- [`db/migration/V20__decision_input_v2_managed_asset_context.sql`](db/migration/V20__decision_input_v2_managed_asset_context.sql)\n"""
    if text.count(migration_anchor) != 1:
        raise AssertionError("README migration list anchor mismatch")
    text = text.replace(migration_anchor, migration_extra, 1)

    old_epss = "- CVSS وCISA KEV لديهما مسارات collection/handoff مجدولة مستقلة؛ FIRST EPSS يملك source adapter وCSV contract وV12/API/UI، لكن safe handoff المجدول ما يزال increment لاحقاً."
    new_epss = "- CVSS وCISA KEV وFIRST EPSS لديها مسارات source/handoff أوrefresh متحققة بشكل مستقل؛ يبقى كل مصدر مستقلاً ولا يخلق أي منها Risk أوsource precedence بمفرده."
    if text.count(old_epss) != 1:
        raise AssertionError("README EPSS limitation anchor mismatch")
    text = text.replace(old_epss, new_epss, 1)

    old_asset_limit = """## حد Asset Context الحالي\n\nAsset Context أصبحت evidence كاملة من العقد حتى V13 وAPI/UI، لكن **ليست RBVM score**.\nلا يوجد في 0.18.0 source arbitration بين أنظمة السياق، ولا internet exposure/reachability،\nولا numeric criticality multiplier، ولا CVSS+KEV+EPSS+asset formula، ولا remediation SLA مشتق.\nالمرحلة التالية هي Exposure/Reachability evidence مستقلة مع provenance، ثم Business/Mission\nImpact، وبعدها فقط يمكن تثبيت methodology القرار بشكل صريح وقابل للتدقيق.\n## حد Evidence Foundation الحالي\n\nNetwork Reachability وBusiness/Mission Impact أصبحتا evidence مستقلتين كاملتين من العقد حتى PostgreSQL وAPI/UI،\nلكن **لا توجد بعد RBVM decision formula**. `NOT_REACHABLE` تبقى scoped negative evidence فقط، وغياب reachability\nأوimpact row يبقى absence. `Impact_Level` يبقى source-reported qualitative classification ولا يتحول إلى multiplier.\nلا يوجد في 0.18.0 source arbitration أوasset-wide `internetExposed` verdict أوaggregate impact score أوattack-path score\nأوCVSS+KEV+EPSS+Applicability+Asset Context+Reachability+Business Impact formula. المنهجية والTreatment/SLA طبقة لاحقة صريحة.\n"""
    new_asset_limit = """## حد Evidence / Decision Foundation الحالي\n\nحتى 0.23.1 أصبحت Applicability وCVSS وKEV وEPSS وAsset Context وNetwork Reachability وBusiness/Mission Impact\nأدلة مستقلة، وأصبحت `RBVM_DECISION_METHODOLOGY_V1` وDecision Input Snapshot V2 تثبت اختيار الأدلة\nو`PRESENT|MISSING|AMBIGUOUS|STALE` مع provenance تاريخي دقيق. Managed Asset context لا يدخل إلا عبر\nscanner↔managed-asset link صريح customer-confirmed، ولا يوجد source winner مخفي.\n\n**لا توجد بعد RBVM decision formula**. `NOT_REACHABLE` تبقى scoped negative evidence، وغياب أي evidence يبقى\nabsence، وBusiness Criticality/Impact تبقى qualitative classifications بلا multiplier. لا يوجد asset-wide\n`internetExposed` verdict أوaggregate impact/attack-path score أوRisk/Priority/SLA مشتق. Formula V1 هي المرحلة\nالتالية فقط بعد إغلاق pre-V24 live-integration hardening.\n"""
    if text.count(old_asset_limit) != 1:
        raise AssertionError("README stale evidence-foundation block mismatch")
    text = text.replace(old_asset_limit, new_asset_limit, 1)

    write(path, text)


def validation_doc():
    path = ROOT / "docs/PRE_V24_HARDENING.md"
    if path.exists():
        return
    path.write_text("""# Pre-V24 Hardening\n\nThis corrective pass does not define or calculate Risk, Priority, Treatment, or SLA. It closes\noperational proof and UI/documentation debt before `RBVM_FORMULA_V1`.\n\n## Verification boundary\n\n- Standard dependency-free verification and CodeQL remain required.\n- A dedicated PostgreSQL integration workflow migrates a disposable database through V20.\n- The live test uses the restricted `rbvm_runtime` role for V18 managed assets, V19 explicit\n  scanner↔managed-asset links, and V16/V17/V20 Decision Methodology/Input operations.\n- It proves create/revise, LINK/replay/UNLINK/history, V2 build/persist/resolve, historical as-of\n  behavior, and denied UPDATE/DELETE against append-only tables.\n- PostgreSQL CI uses a digest-pinned PostgreSQL 16.12 image and pgJDBC 42.7.13 with a pinned\n  SHA-256. TLS is intentionally disabled only on the loopback disposable CI service; production\n  TLS remains a deployment control documented separately.\n\n## UI corrections\n\nManaged Asset creation no longer defaults Environment, Business Criticality, or Classification\nMethod to meaningful customer values. The operator must choose each explicitly. Table captions\nremain available to assistive technology, guide revisions use integer stepping, and the revision\nflow avoids stacking one modal dialog on top of another.\n\n## Formula boundary\n\nNo formula, numeric criticality multiplier, source precedence, priority tier, or SLA rule is added\nby this pass. V24 remains the Formula contract increment after these gates are green.\n""", encoding="utf-8")


version_alignment()
managed_assets_ui()
managed_assets_ui_verifier()
readme()
validation_doc()
print("pre-V24 exact hardening patch: PASS")
