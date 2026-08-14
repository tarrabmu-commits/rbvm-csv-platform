# عقد WAZUH_CSV_V2

V2 عقد opt-in لمن يملك دليلاً صريحاً عن هوية الأصل والحزمة ودورة حياة الـfinding.
يُختار عبر `X-CSV-Contract: WAZUH_CSV_V2`؛ حذف الـheader يبقي V1 كما هو.

## الأعمدة

```text
Agent,Agent_ID,CVE_ID,Severity,CVE_Description,Affected_Product,
Package_Version,Package_Architecture,References,OS_name,Finding_Status,
Detected_At,Resolved_At
```

`Agent_ID` و`Package_Version` و`Package_Architecture` و`Finding_Status` حقول لازمة.
الحالة تقبل `ACTIVE` أو`RESOLVED` فقط. صف `ACTIVE` يمنع `Resolved_At`، وصف
`RESOLVED` يتطلب وقت ISO-8601 لا يسبق `Detected_At`.

## الهوية والزمن

```text
Asset = source profile + normalized Agent_ID
Component = Asset + normalized product + version + architecture
Exposure = Asset + CVE + Component
Case = Asset + CVE
```

آخر دليل صريح زمنياً يحدد حالة Exposure. عند دليلين متعارضين في اللحظة نفسها
تفوز `ACTIVE` لتجنب false closure. تغلق Case تقنياً إلى `SOURCE_RESOLVED` فقط عندما
تكون كل Exposures التابعة لها `RESOLVED`. ظهور `ACTIVE` أحدث يعيدها إلى `OPEN`.

لا يدل غياب صف من أي ملف لاحق على الحل، ولا ينفذ النظام absence-based close.
قرارات Workflow البشرية (`ACCEPTED_RISK`, `FALSE_POSITIVE`, `CLOSED_MANUAL`) لا
يستبدلها الاستيراد تلقائياً.

هذا عقد منصة RBVM محسّن، ولا يُفترض أن كل تصدير Wazuh جاهز يوفّر أعمدته من دون
تهيئة مصدر موثوقة.
