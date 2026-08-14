# النموذج الموحّد ومعالجة Wazuh CSV

## حدود الهوية

ملف `WAZUH_CSV_V1` لا يحمل Agent ID ثابتاً ولا package version. لذلك يمنع النموذج
الاستنتاجات الأقوى من الدليل:

| الكيان | المفتاح الطبيعي في V1 | القيد المقصود |
|---|---|---|
| Asset | Tenant + Source Profile + normalized Agent | لا دمج بين Profile وآخر |
| Vulnerability | CVE uppercase | مرجع CVE فقط؛ الوصف يبقى Snapshot في Observation |
| Component | Asset + normalized product | النسخة `UNKNOWN_FROM_SOURCE` |
| Observation | Source Profile + canonical fingerprint | دليل غير قابل للتعديل |
| Exposure | Asset + CVE + Component + Source Profile | يجمع إعادة المشاهدة للمنتج نفسه |
| Case | Asset + CVE + Source Profile | يجمع عدة Components/Exposures |

المعرّفات العامة التي يعرضها التشغيل المحلي SHA-256 مشتقة من namespace والمفتاح
الطبيعي. مخطط PostgreSQL يستخدم UUID داخلياً مع Unique constraints على المفاتيح
الطبيعية نفسها.

## مراحل المعالجة

1. حفظ body المرفوع Streaming في Staging مع حد للحجم.
2. حساب SHA-256 والتحقق من UTF-8 وعقد الأعمدة.
3. تحليل RFC 4180 والتحقق من الصفوف.
4. بناء fingerprint ثابت لا يتغير عند إعادة ترتيب الأعمدة.
5. عزل الصف غير الصالح ومنع الصف المتطابق داخل الملف.
6. عند التأكيد، فتح transaction للمادية.
7. ربط Observation موجودة أوإنشاء Observation جديدة.
8. Upsert للـAsset وVulnerability وComponent.
9. Upsert للـExposure وفق وقت الحدث `Detected_At`، لا وفق ترتيب CSV.
10. إعادة حساب Case من Exposures الحالية ثم Commit ذري.
11. حفظ Materialization ledger وربطه بـImport Run.

التشغيل المحلي ينفذ الخطوات 6–10 بأسلوب copy-on-write: لا يتم تبديل الكاتالوج
الحالي إلا بعد انتهاء الملف. عند تفعيل PostgreSQL، يعاد إسقاط الدليل نفسه داخل
معاملة Serializable قبل اعتماد Import كـ`COMPLETED`، ثم تقرأ API من PostgreSQL.
يبقى النموذج المحلي للتحقق والتعافي؛ راجع [`POSTGRES_PROJECTION.md`](POSTGRES_PROJECTION.md).

## الزمن والخطورة

- `first_observed_at` هو أصغر `Detected_At`.
- `last_observed_at` هو أكبر `Detected_At`.
- خطورة Exposure الحالية تأتي من أحدث Observation زمنياً، لا من آخر صف في الملف.
- إذا حملت Observationان Severity مختلفتين في التوقيت نفسه، يسجل
  `timestamp_severity_conflict=true` وتختار الأعلى تحفظياً وبشكل deterministic.
- خطورة Case الحالية هي أعلى خطورة حالية بين Exposures المرتبطة بها.
- `UNKNOWN` قيمة مستقلة ولا تساوي Low أوصفر.

## الإغلاق

جميع Exposures وCases الجديدة تبدأ `OPEN`. الملف Positive-only ومتعدد الأزمنة،
وبالتالي:

```text
غياب السجل في CSV لاحقة ≠ remediation ≠ closure
```

الإغلاق التلقائي ممنوع. الانتقال إلى `ACCEPTED_RISK` أو`FALSE_POSITIVE` أو
`CLOSED_MANUAL` يتطلب قرار Workflow صريحاً مع السبب وسجل تدقيق. `REOPEN` يعيد أي
حالة غير مفتوحة إلى `OPEN`، و`COMMENT` يضيف حدثاً بلا تغيير الحالة. راجع
[`CASE_WORKFLOW.md`](CASE_WORKFLOW.md) لآلة الانتقالات وقواعد idempotency والتعافي.

## نتيجة الملف المرجعي بعد المادية

| الكيان/المؤشر | العدد |
|---|---:|
| Observations | 10,001 |
| Assets | 5 |
| Vulnerabilities | 2,265 |
| Asset-scoped Components | 602 |
| Exposures | 9,090 |
| Cases | 7,521 |
| Open Cases | 7,521 |
| Auto-closed Cases | 0 |
| Exposures تغيّرت خطورتها | 226 |
| تعارض Severity في التوقيت نفسه | 0 |

عدد Components أكبر من عدد أسماء المنتجات الفريدة (`221`) لأن المنتج نفسه على
أصلين مختلفين يمثل مكوّنين متأثرين مختلفين.
