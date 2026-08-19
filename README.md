# RBVM CSV Platform — Increment 18

منصة محلية قابلة للتشغيل لإدخال `WAZUH_CSV_V1` أوعقد `WAZUH_CSV_V2` الاختياري وتحويل الأدلة إلى
نموذج RBVM موحّد: Assets وVulnerabilities وComponents وObservations وExposures
وCases، مع حفظ الدليل الخام وإدارة قرارات الحالة بسجل تدقيق قابل لإعادة البناء،
وقراءة وكتابة كانونـية اختيارية عبر PostgreSQL.

## ما الذي يعمل الآن؟

- واجهة عربية لرفع CSV والمعاينة ثم اعتماد المادية.
- HTTP API ورفع Streaming بحد افتراضي `100 MiB`.
- RFC 4180 وUTF-8 صارم، بما فيه الحقول ذات الأسطر الداخلية.
- تحقق من headers وCVE والتوقيت والحقول المطلوبة.
- V2 يضيف Agent ID ثابتاً وإصدار/معمارية الحزمة و`ACTIVE|RESOLVED` مع وقت حل صريح.
- المسار القديم الذي يجمع CVSS/EPSS/KEV داخل V2 ما يزال موجوداً للتوافق، لكنه ليس نموذج الاستخبارات الكانوني الجديد.
- Applicability مستقلة عن Wazuh عبر `APPLICABILITY_CSV_V1` مع `APPLICABLE|NOT_APPLICABLE|UNKNOWN` وprovenance ووقت تقييم صريح.
- CVSS v3.1 Base مستقلة عبر `CVSS_V31_CSV_V1` كدليل Technical Severity على مستوى CVE، مع source وobserved-at خاصين بها.
- CISA KEV مستقلة عبر `CISA_KEV_CSV_V1` كدليل Threat Evidence مربوط بلقطة كاملة ومتحقق منها، مع `LISTED|NOT_LISTED` وprovenance صريح؛ غياب الدليل يبقى `UNKNOWN`.
- FIRST EPSS مستقلة عبر `EPSS_CSV_V1` كدليل exploitation probability على مستوى CVE، مع probability وpercentile وmodel version وscore date وsource SHA-256؛ غياب score evidence لا يتحول إلى `0`.
- Asset Context مستقلة عبر `ASSET_CONTEXT_CSV_V1` كدليل تنظيمي على مستوى الـAsset، مع Environment وBusiness Service وOwner وqualitative Business Criticality وsource SHA-256؛ ولا تتحول هذه القيم تلقائياً إلى risk أوpriority.
- Network Reachability مستقلة عبر `NETWORK_REACHABILITY_CSV_V1` كدليل تقني scoped حسب origin + endpoint + source + time؛ غياب row لا يعني `NOT_REACHABLE`، و`NOT_REACHABLE` لا يعني global isolation.
- Business/Mission Impact مستقلة عبر `BUSINESS_IMPACT_CSV_V1` كدليل نوعي source-reported على مستوى Asset + Business Service + impact dimension؛ `SEVERE|HIGH|MODERATE|LOW|NEGLIGIBLE|UNKNOWN` تبقى classifications بلا numeric weight.
- PostgreSQL V9 يحفظ Applicability history، V10 يحفظ CVSS history، V11 يحفظ CISA KEV snapshot-bound history، V12 يحفظ EPSS score snapshots وCVE score history، وV13 يحفظ immutable Asset Context snapshots/evidence، وV14 يحفظ immutable scoped Network Reachability snapshots/evidence، وV15 يحفظ immutable qualitative Business/Mission Impact snapshots/evidence.
- API مخصصة لاستيراد Applicability وCVSS وKEV وEPSS وAsset Context وNetwork Reachability وBusiness/Mission Impact وقراءة current evidence، مع صفحات تشغيل مستقلة على `/cvss` و`/kev` و`/epss` و`/asset-context` و`/reachability` و`/business-impact`.
- current CVSS/KEV/EPSS وAsset Context وNetwork Reachability وBusiness/Mission Impact evidence تبقى per-source من دون اختيار winner مخفي أوthreshold-to-priority mapping؛ Business Criticality تبقى qualitative evidence فقط.
- ملخص coverage وfreshness للاستخبارات القديمة مع حد stale معلن قدره 7 أيام وتوزيع الأولوية.
- تحديث استخبارات مجدول وآمن مع cache مربوط ببصمة CVE ولقطات ذرية قابلة للعمل offline.
- حل تقني وإعادة فتح من دليل V2 صريح فقط؛ لا يوجد أي إغلاق مبني على غياب الصف.
- Fingerprint دلالية ثابتة لا تتغير عند إعادة ترتيب الأعمدة.
- Idempotency على مفتاح الطلب و`source profile + file SHA-256`.
- Observation immutable ومنع تكرارها داخل الملف وبين الاستيرادات.
- هوية Asset ضعيفة ومقيدة بالـSource Profile لغياب Wazuh Agent ID.
- Component مقيد بالـAsset لأن المنتج نفسه على جهازين تعرّضان مختلفان.
- Exposure تعتمد وقت الحدث، لا ترتيب صفوف CSV.
- Case تجمع Exposures للـAsset+CVE وتحتفظ بأعلى خطورة حالية.
- بحث الحالات حسب Severity وStatus وCVE وAsset مع cursor pagination ثابتة.
- حالات Workflow صريحة: قبول المخاطر، False Positive، إغلاق يدوي، إعادة فتح، وتعليق.
- كل قرار idempotent ويُحفظ كحدث append-only مع السبب والفاعل ومستوى الثقة به.
- انتهاء قبول المخاطر يظهر كإشارة ولا يغيّر الحالة بصمت من دون حدث مدقّق.
- Copy-on-write transaction: أي فشل أثناء CSV لا يترك كاتالوجاً جزئياً.
- حفظ `source.csv` و`analysis.json` و`materialization.json` وmetadata.
- إعادة تحقق وبناء الكاتالوج من الأدلة المحفوظة عند إعادة التشغيل.
- PostgreSQL projection متزامنة: Import لا يكتمل قبل Commit معاملة قاعدة البيانات.
- إعادة إرسال آمنة للـImports وأحداث Workflow من الأدلة المحلية بعد الانقطاع.
- PostgreSQL Read Catalog لملخص الكاتالوج والبحث وتفاصيل الحالات.
- Migration runner بتدقيق SHA-256 وقفل PostgreSQL advisory وتسلسل V1–V15.
- دور Runtime محدود، وحراس append-only يمنعون تعديل أوحذف أدلة التدقيق وApplicability/CVSS/KEV/EPSS/Asset Context history.
- TLS `verify-full` وأدوات Backup/Restore واختبار قطع الاتصال.
- Health يصرّح بمصدر القراءة وحالة PostgreSQL reconciliation وبقدرات Applicability وCVSS v3.1 وCISA KEV وEPSS وAsset Context.
- Bearer API keys ببصمات SHA-256 فقط وRBAC لأدوار Viewer/Operator/Admin.
- هوية Actor موثقة في Audit Trail، مع liveness/readiness وPrometheus metrics.
- انتهاء اختياري لمفاتيح API وحدود طلبات مستقلة للـActors ومحاولات الدخول الفاشلة.
- Readiness عامة قليلة المعلومات، بينما Health التفصيلية محمية بدور Viewer.
- JAR reproducible مع SHA-256 وSPDX 2.3 SBOM وGitHub artifact attestations.
- كل GitHub Action مثبت على commit SHA كامل، مع CodeQL وجدول release موثّق.
- GitHub Actions للتحقق والبناء، واختبار تعافي حي بعد إعادة تشغيل PostgreSQL.
- OpenAPI 0.18.0 موحّد مع runtime Applicability/CVSS/CISA KEV/EPSS/Asset Context/Network Reachability/Business Impact الحالي، إضافة إلى migrations واختبارات contract/domain/HTTP.

## التشغيل المحلي

تشغيل الخادم يحتاج JDK 17 أوأحدث فقط ولا توجد مكتبات runtime خارجية. حزمة التحقق
للمطور تحتاج أيضاً Python 3 وPyYAML لتدقيق OpenAPI وSQL.

```bash
./scripts/verify.sh
./scripts/run-server.sh
```

ثم افتح:

```text
http://127.0.0.1:8080
```

واجهة CVSS v3.1 المستقلة:

```text
http://127.0.0.1:8080/cvss
```

واجهة CISA KEV المستقلة:

```text
http://127.0.0.1:8080/kev
```

واجهة FIRST EPSS المستقلة:

```text
http://127.0.0.1:8080/epss
```

واجهة Asset Context المستقلة:

```text
http://127.0.0.1:8080/asset-context
```

واجهة Network Reachability المستقلة:

```text
http://127.0.0.1:8080/reachability
```

واجهة Business/Mission Impact المستقلة:

```text
http://127.0.0.1:8080/business-impact
```

لبناء JAR مستقل:

```bash
./scripts/build-distribution.sh
java -jar dist/rbvm-csv-platform-0.18.0.jar
```

ولتشغيل الاختبارات ثم تحليل ملف من CLI:

```bash
./scripts/verify.sh /absolute/path/to/test.csv
```

للتحقق أن البنية قابلة لإعادة الإنتاج byte-for-byte، مع checksum وSBOM:

```bash
./scripts/verify-reproducible-build.sh
sha256sum --check dist/rbvm-csv-platform-0.18.0.jar.sha256
```

ينشر tag مطابق مثل `v0.18.0` Release يحتوي JAR وchecksum وSPDX SBOM، ويولد
GitHub build-provenance وSBOM attestations. يتحقق workflow من تطابق tag مع
Gradle وOpenAPI واسم الحزمة قبل النشر.

## الإعدادات

| Environment variable | القيمة الافتراضية | الوظيفة |
|---|---:|---|
| `RBVM_HOST` | `127.0.0.1` | عنوان الاستماع المحلي |
| `RBVM_PORT` | `8080` | منفذ HTTP |
| `RBVM_DATA_DIR` | `data` | أدلة الاستيراد والـmetadata |
| `RBVM_MAX_UPLOAD_BYTES` | `104857600` | الحد الأعلى لحجم CSV |
| `RBVM_PROJECTION_BACKEND` | `DISABLED` | استخدم `POSTGRESQL` لتفعيل الإسقاط |
| `RBVM_JDBC_URL` | — | رابط `jdbc:postgresql:` عند التفعيل |
| `RBVM_DB_USER` | — | مستخدم قاعدة البيانات |
| `RBVM_DB_PASSWORD` | — | كلمة المرور؛ لا تظهر في Health أوLogs |
| `RBVM_DB_MIGRATE` | `true` | تطبيق migrations المفقودة عند الإقلاع |
| `RBVM_POSTGRES_DRIVER_JAR` | — | مسار pgJDBC المستخدم بواسطة script التشغيل |
| `RBVM_AUTH_MODE` | `DISABLED` | استخدم `API_KEY` لرفض الوصول غير الموثق |
| `RBVM_API_KEYS_FILE` | — | ملف `digest=actor-id\|ROLE` ببصمات SHA-256؛ يمنع التشغيل أي POSIX group/other permissions |
| `RBVM_RATE_LIMIT_PER_MINUTE` | `600` | الحد الثابت لكل Actor موثّق؛ القيمة `0` تعطل الحد |
| `RBVM_AUTH_FAILURE_LIMIT_PER_MINUTE` | `60` | حد محاولات الدخول الفاشلة لكل عنوان مصدر |

## تحديث FIRST EPSS المجدول

المسار الكانوني المستقل لـEPSS مكتمل أيضاً: `scheduled-epss-refresh.sh` يجلب أويعيد تشغيل
لقطة FIRST bulk متحققاً منها، يبني `EPSS_CSV_V1`، ثم يسلّم نفس البايتات إلى
`POST /api/v1/epss-imports` بمفتاح API مخصص. لا يتقدم `latest` إلا بعد نجاح الـAPI import،
وأي فشل fetch/build/handoff يبقي آخر لقطة منشورة سليمة كما هي. وحدتا
`rbvm-epss-refresh.service` و`rbvm-epss-refresh.timer` توفران جدولة يومية مع قفل يمنع
التشغيل المتداخل وretention للقطات المكتملة.

## تحديث استخبارات الثغرات المجدول

ينشئ `scripts/scheduled-intelligence-refresh.sh` لقطة enriched ذرية من ملف V2
حالي، مع checksum وتقرير JSON وروابط `latest.csv` و`latest.csv.sha256` و`latest.json`. يربط cache
ببصمة مجموعة CVE كي لا يعيد وضع offline بيانات دفعة سابقة مختلفة، ويحتفظ افتراضياً
بآخر 14 لقطة. هذا المسار هو compatibility للـlegacy combined intelligence ولا يغيّر
العقود المستقلة لـCVSS v3.1 أوCISA KEV أوFIRST EPSS. لا يرفع المشغّل الناتج إلى API تلقائياً، لأن إعادة استيراد
تصدير قديم قد تعيد حالة finding من دليل lifecycle متقادم؛ يظل الاعتماد خطوة صريحة على
تصدير Wazuh الحالي.

انسخ `deploy/intelligence-refresh.example` إلى
`~/.config/rbvm-platform/intelligence-refresh.env` بصلاحية `0600`، ثم ثبّت وحدتي
`rbvm-intelligence-refresh.service` و`rbvm-intelligence-refresh.timer` من
`deploy/systemd/` وفعّل المؤقت. مفتاح `NVD_API_KEY` اختياري ولا يوضع في URL أو
ملف الناتج.

أنشئ مفتاحاً من دون وضع القيمة الخام في environment أوGit:

```bash
./scripts/create-api-key.sh ~/.config/rbvm/api-keys.conf \
  ~/.config/rbvm/operator.token soc-operator OPERATOR
```

يمكن إضافة وقت انتهاء UTC كوسيط خامس، ثم تدوير المفتاح بإضافة البديل وإعادة
التشغيل، توزيع البديل، وإلغاء القديم:

```bash
./scripts/create-api-key.sh ~/.config/rbvm/api-keys.conf \
  ~/.config/rbvm/operator-next.token soc-operator OPERATOR 2026-12-31T23:59:59Z
systemctl --user restart rbvm-csv-platform
./scripts/revoke-api-key.sh ~/.config/rbvm/api-keys.conf ~/.config/rbvm/operator.token
systemctl --user restart rbvm-csv-platform
```

الأدوار متدرجة: `VIEWER` للقراءة وmetrics، و`OPERATOR` يضيف الاستيراد والقرارات،
و`ADMIN` يحتفظ بكل صلاحيات API. صفحة الويب تطلب القيمة الخام وتحفظها في
`sessionStorage` فقط طوال نافذة المتصفح.

## API الأساسية

رفع ملف Wazuh:

```bash
curl -X POST http://127.0.0.1:8080/api/v1/csv-imports \
  -H "Authorization: Bearer $RBVM_API_TOKEN" \
  -H 'Content-Type: text/csv' \
  -H 'X-Source-Profile-Id: accepted-wazuh-csv' \
  -H 'Idempotency-Key: upload-20260720-0001' \
  --data-binary @test.csv
```

لاستخدام V2 أضف `-H 'X-CSV-Contract: WAZUH_CSV_V2'` واستعمل Source Profile
مخصصاً لهذا العقد. حذف الـheader يعني V1 حفاظاً على التوافق.

اعتماد المادية:

```bash
curl -X POST \
  http://127.0.0.1:8080/api/v1/csv-imports/IMPORT_ID/confirm \
  -H "Authorization: Bearer $RBVM_API_TOKEN" \
  -H 'Idempotency-Key: confirm-20260720-0001'
```

Applicability:

```bash
curl -H "Authorization: Bearer $RBVM_API_TOKEN" \
  http://127.0.0.1:8080/api/v1/applicability-findings.csv \
  -o rbvm-applicability-findings.csv

curl -X POST http://127.0.0.1:8080/api/v1/applicability-imports \
  -H "Authorization: Bearer $RBVM_API_TOKEN" \
  -H 'Content-Type: text/csv' \
  --data-binary @applicability.csv
```

CVSS v3.1 Base Technical Severity:

```bash
curl -X POST http://127.0.0.1:8080/api/v1/cvss-v31-imports \
  -H "Authorization: Bearer $RBVM_API_TOKEN" \
  -H 'Content-Type: text/csv' \
  --data-binary @cvss-v31.csv

curl -H "Authorization: Bearer $RBVM_API_TOKEN" \
  'http://127.0.0.1:8080/api/v1/cvss-v31-evidence?limit=100&cve=CVE-2026-'
```

`/api/v1/cvss-v31-evidence` يعرض أحدث evidence **لكل source على حدة**؛ لا يختار
المحرك source فائزاً ولا يحوّل CVSS إلى Priority أوRisk Score أوSLA.

قراءة الكاتالوج:

```bash
curl -H "Authorization: Bearer $RBVM_API_TOKEN" http://127.0.0.1:8080/api/v1/catalog/summary
curl -H "Authorization: Bearer $RBVM_API_TOKEN" 'http://127.0.0.1:8080/api/v1/cases?limit=20&severity=CRITICAL,HIGH&status=OPEN'
```

قراءة حالة محددة وسجل تدقيقها:

```bash
curl -H "Authorization: Bearer $RBVM_API_TOKEN" http://127.0.0.1:8080/api/v1/cases/CASE_ID
```

تسجيل قرار قبول مخاطر:

```bash
curl -X POST http://127.0.0.1:8080/api/v1/cases/CASE_ID/actions \
  -H "Authorization: Bearer $RBVM_API_TOKEN" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Idempotency-Key: case-action-20260720-0001' \
  --data-urlencode 'action=ACCEPT_RISK' \
  --data-urlencode 'reason=Risk approved by the local operator' \
  --data-urlencode 'expiresAt=2026-12-31T23:59:59Z'
```

العقد الكامل في [`api/openapi.yaml`](api/openapi.yaml).

المساران `/api/v1/live` و`/api/v1/ready` عامان وقليلا المعلومات لكي تستخدمهما
probes، بينما `/api/v1/health` و`/api/v1/metrics` يحتاجان دور `VIEWER` أوأعلى.
الخدمة الافتراضية تستمع على loopback؛
عند نشرها خارج الجهاز يجب وضع TLS reverse proxy موثوق أمامها وعدم إرسال Bearer token عبر HTTP.

CISA KEV Threat Evidence:

```bash
curl -X POST http://127.0.0.1:8080/api/v1/cisa-kev-imports \
  -H "Authorization: Bearer $RBVM_API_TOKEN" \
  -H 'Content-Type: text/csv' \
  --data-binary @cisa-kev.csv

curl -H "Authorization: Bearer $RBVM_API_TOKEN" \
  'http://127.0.0.1:8080/api/v1/cisa-kev-evidence?limit=100&cve=CVE-2026-'
```

`NOT_LISTED` يعني أن الـCVE غير موجود في لقطة KEV كاملة ومتحقق منها؛ لا يعني أن الثغرة آمنة أو غير مستغلة. `KEV_Due_Date` يبقى دليل مصدر من CISA ولا يتحول تلقائياً إلى SLA للمؤسسة.

FIRST EPSS Exploitation Probability Evidence:

```bash
curl -X POST http://127.0.0.1:8080/api/v1/epss-imports \
  -H "Authorization: Bearer $RBVM_API_TOKEN" \
  -H 'Content-Type: text/csv' \
  --data-binary @epss.csv

curl -H "Authorization: Bearer $RBVM_API_TOKEN" \
  'http://127.0.0.1:8080/api/v1/epss-evidence?limit=100&cve=CVE-2026-'
```

EPSS probability وpercentile تبقيان evidence من FIRST وليستا Risk Score أوPriority. `EPSS_Score_Date` هو تاريخ score المنشورة، بينما `EPSS_Observed_At` وقت حصول المنصة على الدليل؛ والـCVE المفقودة لا تتحول إلى probability بقيمة صفر.


### Business/Mission Impact evidence

استيراد evidence نوعية source-reported:

```bash
curl -H "Authorization: Bearer $RBVM_API_KEY" \
  -H 'Content-Type: text/csv' \
  --data-binary @business-impact.csv \
  http://127.0.0.1:8080/api/v1/business-impact-imports
```

قراءة current evidence مع filters تشغيلية فقط:

```bash
curl -H "Authorization: Bearer $RBVM_API_KEY" \
  'http://127.0.0.1:8080/api/v1/business-impact-evidence?businessService=checkout&impactDimension=MISSION&impactLevel=SEVERE&limit=100'
```

القراءة لا تختار source winner، ولا تحوّل `Impact_Level` إلى وزن رقمي، ولا تجمع Business Impact مع Asset Context أوReachability أوCVSS/KEV/EPSS إلى Risk/Priority/SLA.

### Network Reachability evidence

استيراد evidence تقنية scoped:

```bash
curl -H "Authorization: Bearer $RBVM_API_KEY" \
  -H 'Content-Type: text/csv' \
  --data-binary @network-reachability.csv \
  http://127.0.0.1:8080/api/v1/network-reachability-imports
```

قراءة current scoped evidence مع filters تشغيلية فقط:

```bash
curl -H "Authorization: Bearer $RBVM_API_KEY" \
  'http://127.0.0.1:8080/api/v1/network-reachability-evidence?asset=web-&originScope=INTERNET&reachabilityStatus=REACHABLE&limit=100'
```

القراءة لا تشتق `internetExposed` على مستوى asset ولا تختار source winner ولا تحسب Risk/Priority/SLA.

## نتيجة CSV المرجعية

| المؤشر | النتيجة |
|---|---:|
| Observations | 10,001 |
| Assets | 5 |
| Vulnerabilities | 2,265 |
| Asset Components | 602 |
| Exposures | 9,090 |
| Cases | 7,521 |
| Open Cases | 7,521 |
| Auto-closed Cases | 0 |
| Exposures with severity changes | 226 |

## التخزين وإعادة البناء

```text
data/
  imports/
    <import-id>/
      source.csv
      analysis.json
      materialization.json
      metadata.properties
  workflow/
    case-events/
      <sequence>-<event-id>.properties
  staging/
```

عند تعطيل PostgreSQL، الكاتالوج المحلي Projection مشتقة في الذاكرة ويعاد بناؤها من
`source.csv`. عند تفعيله، تقرأ API الملخص والحالات والتفاصيل من PostgreSQL، بينما
تبقى الملفات الخام وCase Event journal دليل التعافي وليست Cache قابلة للحذف.

## PostgreSQL

المخطط المستهدف موجود في:

- [`db/migration/V1__canonical_rbvm.sql`](db/migration/V1__canonical_rbvm.sql)
- [`db/migration/V2__dashboard_views.sql`](db/migration/V2__dashboard_views.sql)
- [`db/migration/V3__case_workflow_audit.sql`](db/migration/V3__case_workflow_audit.sql)
- [`db/migration/V4__postgres_projection_runtime.sql`](db/migration/V4__postgres_projection_runtime.sql)
- [`db/migration/V5__postgres_read_catalog.sql`](db/migration/V5__postgres_read_catalog.sql)
- [`db/migration/V6__explicit_finding_lifecycle.sql`](db/migration/V6__explicit_finding_lifecycle.sql)
- [`db/migration/V7__vulnerability_intelligence.sql`](db/migration/V7__vulnerability_intelligence.sql)
- [`db/migration/V8__operational_analytics.sql`](db/migration/V8__operational_analytics.sql)
- [`db/migration/V9__applicability_persistence.sql`](db/migration/V9__applicability_persistence.sql)
- [`db/migration/V10__cvss_v31_base_persistence.sql`](db/migration/V10__cvss_v31_base_persistence.sql)
- [`db/migration/V11__cisa_kev_persistence.sql`](db/migration/V11__cisa_kev_persistence.sql)
- [`db/migration/V12__epss_persistence.sql`](db/migration/V12__epss_persistence.sql)
- [`db/migration/V13__asset_context_persistence.sql`](db/migration/V13__asset_context_persistence.sql)
- [`db/migration/V14__network_reachability_persistence.sql`](db/migration/V14__network_reachability_persistence.sql)
- [`db/migration/V15__business_impact_persistence.sql`](db/migration/V15__business_impact_persistence.sql)

لتفعيل الإسقاط، ضع pgJDBC على الـclasspath من دون تضمينه داخل حزمة التطبيق:

```bash
export RBVM_PROJECTION_BACKEND=POSTGRESQL
export RBVM_POSTGRES_DRIVER_JAR=/opt/jdbc/postgresql.jar
export RBVM_JDBC_URL='jdbc:postgresql://db.example/rbvm?sslmode=verify-full'
export RBVM_DB_USER=rbvm_app
export RBVM_DB_PASSWORD='from-a-secret-manager'
./scripts/check-postgres.sh
./scripts/run-server.sh
```

المخطط يثبت Tenant boundaries والمفاتيح الطبيعية والـforeign keys والـindexes
وسياسة V1 الإيجابية وسياسة V2 القائمة على دليل lifecycle صريح. يكتب المحرك البيانات والأحداث داخل
معاملات Serializable ويقرأ الكاتالوج من PostgreSQL. Applicability وCVSS وCISA KEV وEPSS histories
append-only؛ CVSS/KEV/EPSS current views تبقى per-source من دون source precedence مخفي، وEPSS current ordering يقدّم `score_date` على وقت الاستحواذ حتى replay قديم لا يستبدل score أحدث.
استخدم دور مالك للمigrations ودور Runtime محدود للتشغيل اليومي؛ راجع وثيقة PostgreSQL وسجل التحقق الحي.

للنسخ الاحتياطي المجدول، يشغّل `scripts/scheduled-backup.sh` نسخة custom مضغوطة،
ويكتب checksum، ثم يعيدها إلى قاعدة تحقق مؤقتة قبل اعتبارها ناجحة. يحتفظ افتراضياً
بآخر 14 نسخة مطابقة للاسم الآمن فقط؛ يمكن تغيير العدد عبر `RBVM_BACKUP_KEEP` (حده
الأدنى 2). وحدتا systemd المحليتان هما `rbvm-backup.service` و`rbvm-backup.timer`.
قوالب الوحدات وملف البيئة الآمن موجودة تحت [`deploy/`](deploy/).

راجع [`docs/DOMAIN_MODEL.md`](docs/DOMAIN_MODEL.md) لقواعد الهوية والزمن والمادية،
و[`docs/CASE_WORKFLOW.md`](docs/CASE_WORKFLOW.md) لآلة الحالات والتدقيق،
و[`docs/WAZUH_CSV_V1.md`](docs/WAZUH_CSV_V1.md) لعقد المصدر،
و[`docs/WAZUH_CSV_V2.md`](docs/WAZUH_CSV_V2.md) للعقد ذي الهوية والحل الصريح،
و[`docs/APPLICABILITY_CSV_V1.md`](docs/APPLICABILITY_CSV_V1.md) لعقد Applicability المستقل،
و[`docs/CVSS_V31_BASE_EVIDENCE.md`](docs/CVSS_V31_BASE_EVIDENCE.md) لعقد Technical Severity المستقل،
و[`docs/CISA_KEV_EVIDENCE.md`](docs/CISA_KEV_EVIDENCE.md) لحدود Threat Evidence المستقلة،
و[`docs/EPSS_CSV_V1.md`](docs/EPSS_CSV_V1.md) لعقد FIRST EPSS المستقل،
و[`docs/FIRST_EPSS_SOURCE_ADAPTER.md`](docs/FIRST_EPSS_SOURCE_ADAPTER.md) لحد acquisition الرسمي،
و[`docs/EPSS_PERSISTENCE.md`](docs/EPSS_PERSISTENCE.md) لحدود V12 والتاريخ الحالي،
و[`docs/POSTGRES_PROJECTION.md`](docs/POSTGRES_PROJECTION.md) لحدود الإسقاط والتشغيل،
و[`docs/VALIDATION.md`](docs/VALIDATION.md) لنتائج الاختبار الكامل وحدوده.
وسجل [`docs/INCREMENT_6_VALIDATION.md`](docs/INCREMENT_6_VALIDATION.md) لنتائج المحرك الحي.
وسجل [`docs/INCREMENT_7_VALIDATION.md`](docs/INCREMENT_7_VALIDATION.md) للمصادقة والتشغيل الصلب والتعافي.
وسجل [`docs/INCREMENT_8_VALIDATION.md`](docs/INCREMENT_8_VALIDATION.md) لانتهاء المفاتيح وحدود الطلبات وتقليل probe exposure.
وسجل [`docs/INCREMENT_9_VALIDATION.md`](docs/INCREMENT_9_VALIDATION.md) للبناء القابل لإعادة الإنتاج وCodeQL وprovenance.
وسجل [`docs/INCREMENT_10_VALIDATION.md`](docs/INCREMENT_10_VALIDATION.md) لدورة حياة V2 والترحيل V6.
وسجل [`docs/INCREMENT_11_VALIDATION.md`](docs/INCREMENT_11_VALIDATION.md) لـlegacy CVSS/EPSS/KEV وسياسة الأولوية.
وسجل [`docs/INCREMENT_12_VALIDATION.md`](docs/INCREMENT_12_VALIDATION.md) لمراقبة freshness والتحديث المجدول.
وسجل [`docs/INCREMENT_13_VALIDATION.md`](docs/INCREMENT_13_VALIDATION.md) لمحاذاة OpenAPI 0.13 وعقود Applicability وCVSS المستقلة.

## الحدود الحالية

- يوجد API-key RBAC محلي، لكن لا يوجد SSO/OIDC أوMFA أوعزل تنفيذي لعدة Tenants بعد.
- عند `RBVM_AUTH_MODE=DISABLED` يبقى الفاعل `local-operator` غير موثّق؛ وضع الإنتاج هو `API_KEY`.
- الـlegacy combined intelligence اختيارية وتحتاج snapshot حديثاً؛ لا يدعي النظام freshness بعد وقت `Intel_Observed_At`.
- CVSS v3.1 وCISA KEV وFIRST EPSS المستقلة تحفظ evidence per source ولا تطبق source precedence أوformula مشتركة بينها.
- CVSS وCISA KEV لديهما مسارات collection/handoff مجدولة مستقلة؛ FIRST EPSS يملك source adapter وCSV contract وV12/API/UI، لكن safe handoff المجدول ما يزال increment لاحقاً.
- مؤقت legacy enrichment ينتج لقطة جاهزة ومدققة لكنه لا يعتمدها تلقائياً، حفاظاً على دلالة lifecycle الصريحة.
- V1 لا يحمل package version ولا يثبت remediation؛ V2 يثبتها فقط من الحقول الصريحة.
- لا يوجد إغلاق من الغياب؛ `SOURCE_RESOLVED` يحتاج صف V2 صريحاً ومطابقاً.
- تعافي single-node بعد restart مختبر، لكن لا يوجد HA أوMulti-writer؛ مسار الكتابة يستخدم advisory lock واحداً عن قصد.
- TLS المحلي وBackup/Restore مختبران، لكن إدارة الشهادات وRPO/RTO الإنتاجية تعتمد بيئة النشر.

## حد Asset Context الحالي

Asset Context أصبحت evidence كاملة من العقد حتى V13 وAPI/UI، لكن **ليست RBVM score**.
لا يوجد في 0.18.0 source arbitration بين أنظمة السياق، ولا internet exposure/reachability،
ولا numeric criticality multiplier، ولا CVSS+KEV+EPSS+asset formula، ولا remediation SLA مشتق.
المرحلة التالية هي Exposure/Reachability evidence مستقلة مع provenance، ثم Business/Mission
Impact، وبعدها فقط يمكن تثبيت methodology القرار بشكل صريح وقابل للتدقيق.
## حد Evidence Foundation الحالي

Network Reachability وBusiness/Mission Impact أصبحتا evidence مستقلتين كاملتين من العقد حتى PostgreSQL وAPI/UI،
لكن **لا توجد بعد RBVM decision formula**. `NOT_REACHABLE` تبقى scoped negative evidence فقط، وغياب reachability
أوimpact row يبقى absence. `Impact_Level` يبقى source-reported qualitative classification ولا يتحول إلى multiplier.
لا يوجد في 0.18.0 source arbitration أوasset-wide `internetExposed` verdict أوaggregate impact score أوattack-path score
أوCVSS+KEV+EPSS+Applicability+Asset Context+Reachability+Business Impact formula. المنهجية والTreatment/SLA طبقة لاحقة صريحة.

