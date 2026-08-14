# سجل تحقق Increment 5

> هذا السجل تاريخي. تحقق المحرك الحي والـread cutover اللاحق موثق في
> [`INCREMENT_6_VALIDATION.md`](INCREMENT_6_VALIDATION.md).

تاريخ التنفيذ: 2026-07-20

## عينة المصدر

| الخاصية | القيمة |
|---|---|
| العقد | `WAZUH_CSV_V1` |
| حجم الملف | 11,193,882 bytes |
| SHA-256 | `e7ff8e1ff923b3578a7a8c92e85f9c3c7674e283b3187a83377bf8b0a4d6d37d` |
| الصفوف المقبولة | 10,001 |

## النتيجة المادية

| المؤشر | النتيجة |
|---|---:|
| Observations | 10,001 |
| Assets | 5 |
| Vulnerabilities | 2,265 |
| Asset-scoped Components | 602 |
| Exposures | 9,090 |
| Cases | 7,521 |
| Exposures with severity changes | 226 |
| Timestamp severity conflicts | 0 |

## سيناريو Workflow المنفذ

1. رُفع الملف كاملاً ثم انتقل Import من `PREVIEW_READY` إلى `COMPLETED`.
2. قُرئت أول Case حرجة/عالية وهي `OPEN` ومن دون أحداث تدقيق.
3. نُفذ `ACCEPT_RISK` بتاريخ انتهاء مستقبلي، فأصبحت `workflowVersion=1`.
4. أُعيد الطلب بالمفتاح والمحتوى نفسيهما، فأعاد `replayed=true` ولم ينشئ حدثاً آخر.
5. استُخدمت cursor منشأة قبل القرار، فأعاد الخادم `409 Conflict` لأنها Stale.
6. أعيد تشغيل الخادم على دليل البيانات نفسه.
7. أعيد بناء 10,001 Observation والحالة المقبولة وحدث التدقيق الوحيد.
8. أعاد Health الحالة `UP` و`recoveryWarningCount=0`، وتطابق الملخص قبل وبعد التشغيل.

بعد القرار التجريبي أصبح `openCases=7,520` و`ACCEPTED_RISK=1`. هذه القيم تخص
سيناريو التحقق؛ النتيجة الأساسية قبل أي قرار هي 7,521 حالة مفتوحة.

أعيد تشغيل الملف كاملاً بعد تغييرات Increment 5، وسُجل `COMMENT` لا يغيّر Status؛
بقيت الحالات المفتوحة 7,521، ثم استعيد الحدث الوحيد و`workflowVersion=1` بعد Restart
مع Health=`UP` وتطابق الملخص قبل الإيقاف وبعده.

## الاختبارات الآلية

- `CsvContractSelfTest`: UTF-8، RFC 4180، العقد، التطبيع، fingerprint، والأخطاء.
- `DomainCatalogSelfTest`: الهوية، deduplication، event-time، المعاملة، الحالات والتدقيق.
- `CsvHttpSelfTest`: API، رفع/تأكيد، replay، البحث، cursor، القرارات، وإعادة البناء.
- OpenAPI: YAML بلا مفاتيح مكررة، مراجع محلية صالحة وعمليات موثقة.
- SQL: فحص بنيوي لـV1–V4 والقيود الأساسية.
- PostgreSQL grammar: نجح parser مبني على PostgreSQL AST في V1–V4 و38 عبارة SQL
  مضمّنة في JDBC.
- PostgreSQL foundation: إعدادات fail-fast، parser للـSQL، تضمين V1–V4 داخل JAR،
  replay/checksum/rollback للـMigrator، وربط جميع JDBC parameters في معاملات
  Import وCase Event، وحدود إعادة المحاولة من دون تكرار Domain.
- HTML/JavaScript: IDs فريدة وجميع مراجع عناصر الواجهة موجودة.
- Shell scripts: فحص syntax، وفشل PostgreSQL fail-fast من دون تسريب JDBC URL أوPassword.

## حد التحقق

لم تتوفر في بيئة البناء خدمة PostgreSQL فعلية أوpgJDBC. لذلك مسار JDBC compiled
واختُبرت حدوده وإعادة المحاولة تعاقدياً، وV1–V4 خضعت لتدقيق lexical/structural، لكنها
لم تُنفذ بعد على محرك حي ولم تُقاس خططها أوأداؤها. يلزم اختبار PostgreSQL وTLS
وصلاحيات الأدوار قبل أي نشر إنتاجي. كذلك الوضع المحلي بلا مصادقة، لذلك actor
assurance يبقى `UNAUTHENTICATED_LOCAL` عن قصد.
