# RBVM CSV Platform — Increment 5

منصة محلية قابلة للتشغيل لإدخال `WAZUH_CSV_V1` وتحويل مشاهداته الإيجابية إلى
نموذج RBVM موحّد: Assets وVulnerabilities وComponents وObservations وExposures
وCases، مع حفظ الدليل الخام وإدارة قرارات الحالة بسجل تدقيق قابل لإعادة البناء،
وإسقاط كانونـي اختياري إلى PostgreSQL.

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
- Migration runner بتدقيق SHA-256 وقفل PostgreSQL advisory وتسلسل V1–V4.
- Health صريح يفصل Local Read Catalog عن حالة PostgreSQL reconciliation.
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
java -jar dist/rbvm-csv-platform-0.5.0.jar
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

## API الأساسية

رفع ملف:

```bash
curl -X POST http://127.0.0.1:8080/api/v1/csv-imports \
  -H 'Content-Type: text/csv' \
  -H 'X-Source-Profile-Id: accepted-wazuh-csv' \
  -H 'Idempotency-Key: upload-20260720-0001' \
  --data-binary @test.csv
```

اعتماد المادية:

```bash
curl -X POST \
  http://127.0.0.1:8080/api/v1/csv-imports/IMPORT_ID/confirm \
  -H 'Idempotency-Key: confirm-20260720-0001'
```

قراءة الكاتالوج:

```bash
curl http://127.0.0.1:8080/api/v1/catalog/summary
curl 'http://127.0.0.1:8080/api/v1/cases?limit=20&severity=CRITICAL,HIGH&status=OPEN'
curl http://127.0.0.1:8080/api/v1/cases/CASE_ID
```

تسجيل قرار قبول مخاطر:

```bash
curl -X POST http://127.0.0.1:8080/api/v1/cases/CASE_ID/actions \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Idempotency-Key: case-action-20260720-0001' \
  --data-urlencode 'action=ACCEPT_RISK' \
  --data-urlencode 'reason=Risk approved by the local operator' \
  --data-urlencode 'expiresAt=2026-12-31T23:59:59Z'
```

العقد الكامل في [`api/openapi.yaml`](api/openapi.yaml).

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

الكاتالوج المحلي Projection مشتقة في الذاكرة، ويعاد بناؤها من `source.csv` لكل
Import مكتمل عند التشغيل. الملفات الخام هي الدليل وليست Cache قابلة للحذف.

## PostgreSQL

المخطط المستهدف موجود في:

- [`db/migration/V1__canonical_rbvm.sql`](db/migration/V1__canonical_rbvm.sql)
- [`db/migration/V2__dashboard_views.sql`](db/migration/V2__dashboard_views.sql)
- [`db/migration/V3__case_workflow_audit.sql`](db/migration/V3__case_workflow_audit.sql)
- [`db/migration/V4__postgres_projection_runtime.sql`](db/migration/V4__postgres_projection_runtime.sql)

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
وسياسة `POSITIVE_ONLY_NO_AUTO_CLOSE`. يكتب Increment 5 البيانات والأحداث إلى
PostgreSQL داخل معاملات Serializable، لكنه يستمر بالقراءة من الكاتالوج المحلي.
راجع حدود الاتساق وخطة التحويل في وثيقة PostgreSQL.

راجع [`docs/DOMAIN_MODEL.md`](docs/DOMAIN_MODEL.md) لقواعد الهوية والزمن والمادية،
و[`docs/CASE_WORKFLOW.md`](docs/CASE_WORKFLOW.md) لآلة الحالات والتدقيق،
و[`docs/WAZUH_CSV_V1.md`](docs/WAZUH_CSV_V1.md) لعقد المصدر،
و[`docs/POSTGRES_PROJECTION.md`](docs/POSTGRES_PROJECTION.md) لحدود الإسقاط والتشغيل،
و[`docs/VALIDATION.md`](docs/VALIDATION.md) لنتائج الاختبار الكامل وحدوده.

## الحدود الحالية

- لا يوجد Login أوRBAC أوعزل تنفيذي لعدة Tenants بعد.
- الفاعل الحالي `local-operator` ومستوى ثقته `UNAUTHENTICATED_LOCAL`؛ لا يُسوَّق كهوية موثّقة.
- لا يوجد CVSS/EPSS أوThreat Intelligence لأن CSV لا يحملها.
- لا يوجد package version، ولذلك لا نثبت remediation لحزمة.
- لا يوجد Auto-close لأن الملف Positive-only وليس Complete Snapshot.
- PostgreSQL حالياً Write Projection وليست Read Backend أوHA cluster.
- مخطط PostgreSQL وJDBC مدقّقان تعاقدياً، لكن تشغيلهما على محرك PostgreSQL فعلي شرط قبل النشر.
