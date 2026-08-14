# RBVM CSV Platform — Increment 6

منصة محلية قابلة للتشغيل لإدخال `WAZUH_CSV_V1` وتحويل مشاهداته الإيجابية إلى
نموذج RBVM موحّد: Assets وVulnerabilities وComponents وObservations وExposures
وCases، مع حفظ الدليل الخام وإدارة قرارات الحالة بسجل تدقيق قابل لإعادة البناء،
وقراءة وكتابة كانونـية اختيارية عبر PostgreSQL.

## ما الذي يعمل الآن؟

- واجهة عربية لرفع CSV والمعاينة ثم اعتماد المادية.
- HTTP API ورفع Streaming بحد افتراضي `100 MiB`.
- RFC 4180 وUTF-8 صارم، بما فيه الحقول ذات الأسطر الداخلية.
- تحقق من headers وCVE والتوقيت والحقول المطلوبة.
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
- Migration runner بتدقيق SHA-256 وقفل PostgreSQL advisory وتسلسل V1–V5.
- دور Runtime محدود، وحارس append-only يمنع تعديل أوحذف Audit Events.
- TLS `verify-full` وأدوات Backup/Restore واختبار قطع الاتصال.
- Health يصرّح بمصدر القراءة وحالة PostgreSQL reconciliation.
- Bearer API keys ببصمات SHA-256 فقط وRBAC لأدوار Viewer/Operator/Admin.
- هوية Actor موثقة في Audit Trail، مع liveness/readiness وPrometheus metrics.
- GitHub Actions للتحقق والبناء، واختبار تعافي حي بعد إعادة تشغيل PostgreSQL.
- OpenAPI، PostgreSQL migrations، واختبارات contract/domain/HTTP.

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

لبناء JAR مستقل:

```bash
./scripts/build-distribution.sh
java -jar dist/rbvm-csv-platform-0.7.0.jar
```

ولتشغيل الاختبارات ثم تحليل ملف من CLI:

```bash
./scripts/verify.sh /absolute/path/to/test.csv
```

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
| `RBVM_API_KEYS_FILE` | — | ملف `digest=actor-id\|ROLE` ببصمات SHA-256، وصلاحية 600 موصى بها |

أنشئ مفتاحاً من دون وضع القيمة الخام في environment أوGit:

```bash
./scripts/create-api-key.sh ~/.config/rbvm/api-keys.conf \
  ~/.config/rbvm/operator.token soc-operator OPERATOR
```

الأدوار متدرجة: `VIEWER` للقراءة وmetrics، و`OPERATOR` يضيف الاستيراد والقرارات،
و`ADMIN` يحتفظ بكل صلاحيات API. صفحة الويب تطلب القيمة الخام وتحفظها في
`sessionStorage` فقط طوال نافذة المتصفح.

## API الأساسية

رفع ملف:

```bash
curl -X POST http://127.0.0.1:8080/api/v1/csv-imports \
  -H "Authorization: Bearer $RBVM_API_TOKEN" \
  -H 'Content-Type: text/csv' \
  -H 'X-Source-Profile-Id: accepted-wazuh-csv' \
  -H 'Idempotency-Key: upload-20260720-0001' \
  --data-binary @test.csv
```

اعتماد المادية:

```bash
curl -X POST \
  http://127.0.0.1:8080/api/v1/csv-imports/IMPORT_ID/confirm \
  -H "Authorization: Bearer $RBVM_API_TOKEN" \
  -H 'Idempotency-Key: confirm-20260720-0001'
```

قراءة الكاتالوج:

```bash
curl -H "Authorization: Bearer $RBVM_API_TOKEN" http://127.0.0.1:8080/api/v1/catalog/summary
curl -H "Authorization: Bearer $RBVM_API_TOKEN" 'http://127.0.0.1:8080/api/v1/cases?limit=20&severity=CRITICAL,HIGH&status=OPEN'
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

المسارات `/api/v1/live` و`/api/v1/ready` عامة لكي تستخدمها probes، بينما
`/api/v1/metrics` يحتاج دور `VIEWER` أوأعلى. الخدمة الافتراضية تستمع على loopback؛
عند نشرها خارج الجهاز يجب وضع TLS reverse proxy موثوق أمامها وعدم إرسال Bearer token عبر HTTP.

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
وسياسة `POSITIVE_ONLY_NO_AUTO_CLOSE`. يكتب Increment 6 البيانات والأحداث داخل
معاملات Serializable ويقرأ الكاتالوج من PostgreSQL. استخدم دور مالك للمigrations
ودور Runtime محدود للتشغيل اليومي؛ راجع وثيقة PostgreSQL وسجل التحقق الحي.

للنسخ الاحتياطي المجدول، يشغّل `scripts/scheduled-backup.sh` نسخة custom مضغوطة،
ويكتب checksum، ثم يعيدها إلى قاعدة تحقق مؤقتة قبل اعتبارها ناجحة. يحتفظ افتراضياً
بآخر 14 نسخة مطابقة للاسم الآمن فقط؛ يمكن تغيير العدد عبر `RBVM_BACKUP_KEEP` (حده
الأدنى 2). وحدتا systemd المحليتان هما `rbvm-backup.service` و`rbvm-backup.timer`.
قوالب الوحدات وملف البيئة الآمن موجودة تحت [`deploy/`](deploy/).

راجع [`docs/DOMAIN_MODEL.md`](docs/DOMAIN_MODEL.md) لقواعد الهوية والزمن والمادية،
و[`docs/CASE_WORKFLOW.md`](docs/CASE_WORKFLOW.md) لآلة الحالات والتدقيق،
و[`docs/WAZUH_CSV_V1.md`](docs/WAZUH_CSV_V1.md) لعقد المصدر،
و[`docs/POSTGRES_PROJECTION.md`](docs/POSTGRES_PROJECTION.md) لحدود الإسقاط والتشغيل،
و[`docs/VALIDATION.md`](docs/VALIDATION.md) لنتائج الاختبار الكامل وحدوده.
وسجل [`docs/INCREMENT_6_VALIDATION.md`](docs/INCREMENT_6_VALIDATION.md) لنتائج المحرك الحي.
وسجل [`docs/INCREMENT_7_VALIDATION.md`](docs/INCREMENT_7_VALIDATION.md) للمصادقة والتشغيل الصلب والتعافي.

## الحدود الحالية

- يوجد API-key RBAC محلي، لكن لا يوجد SSO/OIDC أوMFA أوعزل تنفيذي لعدة Tenants بعد.
- عند `RBVM_AUTH_MODE=DISABLED` يبقى الفاعل `local-operator` غير موثّق؛ وضع الإنتاج هو `API_KEY`.
- لا يوجد CVSS/EPSS أوThreat Intelligence لأن CSV لا يحملها.
- لا يوجد package version، ولذلك لا نثبت remediation لحزمة.
- لا يوجد Auto-close لأن الملف Positive-only وليس Complete Snapshot.
- تعافي single-node بعد restart مختبر، لكن لا يوجد HA أوMulti-writer؛ مسار الكتابة يستخدم advisory lock واحداً عن قصد.
- TLS المحلي وBackup/Restore مختبران، لكن إدارة الشهادات وRPO/RTO الإنتاجية تعتمد بيئة النشر.
