# دورة حياة الحالة وسجل القرار

هذا المستند هو المرجع التنفيذي لـWorkflow الحالات في Increment 4. الـCase تمثل
`Tenant + Source Profile + Asset + CVE`، بينما القرار البشري يغيّر حالتها ولا يغيّر
الدليل الخام أوObservations أوExposures التي أنشأتها Wazuh.

## الحالات والمعنى

| الحالة | المعنى التشغيلي | هل تعد Open في الملخص؟ |
|---|---|---:|
| `OPEN` | تحتاج معالجة أوقراراً | نعم |
| `ACCEPTED_RISK` | المخاطر مقبولة حتى وقت محدد | لا |
| `FALSE_POSITIVE` | الحالة صُنّفت إنذاراً غير حقيقي بقرار صريح | لا |
| `CLOSED_MANUAL` | أغلقت يدوياً مع مرجع دليل إلزامي | لا |

لا يوجد انتقال آلي بسبب غياب CVE من CSV لاحقة. المصدر Positive-only وليس Complete
Snapshot، ولذلك الغياب لا يثبت remediation.

## آلة الانتقالات

| الفعل | الحالات المصدر المسموحة | الحالة الهدف | المتطلبات الإضافية |
|---|---|---|---|
| `ACCEPT_RISK` | `OPEN`, `ACCEPTED_RISK` | `ACCEPTED_RISK` | `expiresAt` إلزامي وفي المستقبل |
| `MARK_FALSE_POSITIVE` | `OPEN`, `ACCEPTED_RISK` | `FALSE_POSITIVE` | سبب القرار |
| `CLOSE_MANUAL` | `OPEN`, `ACCEPTED_RISK` | `CLOSED_MANUAL` | سبب و`evidenceReference` |
| `REOPEN` | كل حالة غير `OPEN` | `OPEN` | سبب إعادة الفتح |
| `COMMENT` | جميع الحالات | لا تغيير | تعليق محفوظ كحدث تدقيق |

كل الأفعال تتطلب `reason` بطول 1–2000 محرف و`Idempotency-Key` بطول 8–128.
`evidenceReference`، إن وُجد، لا يتجاوز 1000 محرف.

انتهاء `riskAcceptedUntil` يولّد في القراءة `riskAcceptanceExpired=true`، لكنه لا
يغيّر الحالة بصمت. إعادة الفتح أوتجديد القبول يجب أن يكون حدثاً جديداً قابلاً للتدقيق.

## مسار تنفيذ القرار

1. تتحقق طبقة HTTP من المسار ونوع المحتوى وحجم النموذج والحقول المسموحة.
2. يحوّل الطلب إلى `CaseActionCommand` ويتحقق من المدخلات الخاصة بكل فعل.
3. يقفل Service مسار التغييرات ويحل `Idempotency-Key` ضمن نطاق الحالة.
4. يبني Domain حدثاً متوقعاً على `workflowVersion + 1` ويتحقق من الانتقال.
5. يُكتب الحدث إلى ملف جديد في `data/workflow/case-events` قبل تعديل Projection.
6. يطبّق Domain الحدث بعد مطابقة `fromStatus` و`caseVersion`.
7. ترتفع `catalogRevision`، فتصبح cursors القديمة Stale بدلاً من خلط صفحتين مختلفتين.
8. يعاد Case Detail شاملاً الحالة الجديدة والحدث.

ترتيب «حفظ الحدث ثم تطبيقه» مقصود: إذا توقف البرنامج بعد الكتابة وقبل التطبيق، يعاد
تشغيل الحدث من التخزين عند الإقلاع. وإذا أعيد الطلب بالمفتاح نفسه والمحتوى نفسه، يعاد
الحدث السابق؛ أما إعادة المفتاح بمحتوى مختلف فتعيد Conflict ولا تنشئ قراراً ثانياً.

## بنية حدث التدقيق

| الحقل | الغرض |
|---|---|
| `sequence`, `eventId` | ترتيب كلي ومعرّف ثابت للحدث |
| `caseId`, `caseVersion` | الحالة المستهدفة وتسلسلها المتفائل |
| `action`, `fromStatus`, `toStatus` | معنى الانتقال وحدوده |
| `reason`, `expiresAt`, `evidenceReference` | مبررات القرار وقيوده |
| `actorId`, `actorAssurance` | هوية الفاعل ودرجة الثقة بها |
| `occurredAt` | وقت القرار |
| `requestFingerprint` | كشف إعادة استخدام مفتاح idempotency بطلب مختلف |

واجهة القراءة لا تعيد `Idempotency-Key` أو`requestFingerprint` لتقليل كشف بيانات
التحكم، لكنهما محفوظان محلياً ويظهران في مخطط PostgreSQL كقيود نزاهة.

## الثقة والهوية

لا يوجد Login أوRBAC في الوضع المحلي الحالي. لذلك يسجل النظام بصدق:

- `actorId=local-operator`
- `actorAssurance=UNAUTHENTICATED_LOCAL`

هذا Attribution محلي وليس إثبات هوية. قبل الإنتاج يجب ربط الفاعل بهوية موثقة، تطبيق
RBAC، ومنع أدوار التطبيق من `UPDATE` أو`DELETE` على سجل الأحداث.

## البحث والتصفح المتّسق

`GET /api/v1/cases` يقبل `severity`, `status`, `cve`, `asset`, `limit`, و`cursor`.
الترتيب ثابت: Severity تنازلياً، ثم أحدث مشاهدة، ثم `caseId`. الـcursor opaque ويحمل
revision وoffset؛ أي مادية أوقرار جديد يرفع revision، واستخدام cursor قديمة يعيد
`409 Conflict`. هذا يمنع التكرار أوالفقد الصامت بين صفحات مأخوذة من نسختين مختلفتين.

## التخزين المستهدف في PostgreSQL

`V3__case_workflow_audit.sql` يضيف version وبيانات القرار إلى
`rbvm.vulnerability_case`، وينشئ `rbvm.case_audit_event` بقيود على:

- تسلسل نسخة الحالة لكل Tenant وCase.
- تفرد مفتاح idempotency داخل الحالة.
- صلاحية الأفعال والحالات والـSHA-256.
- إلزام تاريخ قبول المخاطر ودليل الإغلاق اليدوي.
- Foreign key مركب يحافظ على Tenant boundary.

View باسم `rbvm.case_workflow_reconciliation` يقارن `workflow_version` بعدد الأحداث
وأعلى `case_version` لاكتشاف فجوة في التسلسل. التنفيذ المحلي يستخدم ملفات append-only؛
أما ضمان عدم UPDATE/DELETE فعلياً في PostgreSQL فيتطلب صلاحيات أدوار مناسبة وقت النشر.

`V4__postgres_projection_runtime.sql` يضيف `public_id` و`source_sequence` للربط
الحتمي مع سجل الأحداث المحلي، ويستخدم sequence مستقلة لترتيب أحداث قاعدة البيانات.
عند تفعيل الإسقاط، Event والحالة وcatalog revision تُكتب في Transaction واحدة.
