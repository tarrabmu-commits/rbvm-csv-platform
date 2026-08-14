# سجل تحقق Increment 6

تاريخ التنفيذ: 2026-08-14. نُفذت البوابات على PostgreSQL 17.10 وpgJDBC 42.7.7
على محرك حي، مع تشغيل API من PostgreSQL Read Catalog.

## النتيجة

| البوابة | النتيجة |
|---|---|
| Migration replay/checksum V1–V5 | PASS |
| ملف مرجعي 10,001 Observation | PASS |
| تطابق Local/PostgreSQL | PASS |
| قطع الاتصال قبل Commit | PASS؛ revision ثابت وpartial rows=0 |
| Import وCase Event idempotency | PASS |
| Reconciliation | PASS؛ صفر مشاكل |
| Query plans | PASS؛ تستخدم indexes المخصصة |
| Audit append-only | PASS بصلاحيات الدور وبـtrigger قاعدة البيانات |
| TLS | PASS؛ TLSv1.3 و`verify-full` |
| Backup/Restore | PASS؛ 10,001 Observation و7,521 Case وAudit Event اثنان |
| PostgreSQL API read cutover | PASS |

## Baseline الحتمي

ينشئ `scripts/generate-reference-csv.py` ملفاً حتمياً يحقق:

| المؤشر | النتيجة |
|---|---:|
| Observations | 10,001 |
| Assets | 5 |
| Vulnerabilities | 2,265 |
| Asset Components | 602 |
| Exposures | 9,090 |
| Cases | 7,521 |
| Exposures with severity changes | 226 |
| Timestamp severity conflicts | 0 |

الملف المولّد في جلسة التحقق كان حجمه `1,573,939` bytes وSHA-256:
`be2151098917c17a7a8ee6fc7239092bb54d063d7220ac0e5c5f1d1c28f9df70`.

## الأداء

على baseline المحلي:

- أول صفحة Cases (`LIMIT 21`) استخدمت `vulnerability_case_catalog_order_idx`
  بزمن تنفيذ يقارب `0.090 ms`.
- ترتيب Exposures حسب Case استخدم `exposure_case_catalog_order_idx` بزمن يقارب
  `1.088 ms` في عينة الخطة.
- عد Cases استخدم Index Only Scan بزمن يقارب `1.046 ms`.

هذه أرقام تطوير محلية وليست SLO إنتاجياً. يجب إعادة القياس على حجم الإنتاج وتزامن
حقيقي قبل اعتماد capacity plan.

## الصلاحيات والنزاهة

- `rbvm_app` مالك المخطط ويطبق migrations فقط.
- `rbvm_runtime` هو دور التشغيل اليومي ولا يملك `UPDATE` أو`DELETE` على
  `case_audit_event`.
- V5 يضيف trigger يرفض `UPDATE/DELETE` على Audit Events حتى لو حاول مالك الجدول.
- التطبيق يعمل بـ`RBVM_DB_MIGRATE=false` مع دور Runtime بعد تطبيق migrations.

## TLS والتعافي

البيئة المحلية تستخدم شهادة مقيدة بـ`localhost` و`127.0.0.1` واتصال JDBC
`sslmode=verify-full`. نجح `pg_stat_ssl` مع TLSv1.3 و`TLS_AES_256_GCM_SHA384`.

نجح Backup بصيغة PostgreSQL custom archive، ثم Restore إلى قاعدة مؤقتة مستقلة.
زمن Backup النهائي كان `303 ms` وزمن Restore `491 ms` محلياً. هذا يثبت قابلية الاستعادة، لكنه لا
يحدد RPO إنتاجياً؛ RPO يعتمد جدولة النسخ وWAL archiving في بيئة النشر.

## أوامر إعادة التحقق

```bash
./scripts/verify.sh
./scripts/verify-live-postgres.sh
./scripts/backup-postgres.sh
./scripts/verify-backup-restore.sh runtime-data/backups/increment6-validation.dump
./scripts/verify-postgres-disconnect.sh runtime-data/backups/increment6-validation.dump
```

## الحدود المتبقية للإنتاج

- المصادقة وRBAC وهوية Actor موثّقة غير منفذة.
- لا يوجد HA أوMulti-writer أوWAL archiving خارجي.
- الشهادة المحلية ليست بديلاً عن PKI وإدارة أسرار إنتاجية.
- مسار الكتابة ما زال serialized بواسطة advisory lock واحد؛ يلزم benchmark قبل تغييره.
- Evidence journal المحلي يبقى Outbox ومصدر إعادة الإرسال، بينما PostgreSQL أصبح
  مصدر قراءة API عند تفعيل Backend.
