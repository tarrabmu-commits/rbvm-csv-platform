# عقد WAZUH_CSV_V1

## البنية المعتمدة

الأعمدة الثمانية المعتمدة هي:

| CSV Header | الحقل الداخلي | الدلالة |
|---|---|---|
| `Agent` | `source_asset.observed_name` | اسم الأصل كما ورد من Wazuh |
| `CVE_ID` | `vulnerability.identifier` | معرّف CVE بعد تحويله إلى uppercase |
| `Severity` | `observation.technical_severity` | Critical/High/Medium/Low/Unknown |
| `CVE_Description` | `observation.description_snapshot` | وصف المصدر وقت المشاهدة |
| `Affected_Product` | `affected_component.name` | اسم الحزمة؛ لا يتضمن الإصدار |
| `References` | `observation.references[]` | روابط المصدر، وتخزن كقائمة |
| `OS_name` | `source_asset.os_name_raw` | قيمة خام، لا نستنتج الإصدار منها |
| `Detected_At` | `observation.source_detected_at` | ISO-8601 مع timezone |

يمكن تغيير ترتيب الأعمدة. الأعمدة الإضافية تقبل وتُسجل، لكن الأعمدة المعتمدة أعلاه
يجب أن تبقى موجودة في Profile V1.

## الحقول اللازمة لقبول صف أمنياً

- `Agent`
- `CVE_ID`
- `Affected_Product`
- `Detected_At`

القيمة `-` في `Severity` تعني `UNKNOWN` ولا تعني صفراً أوLow.

## مفاتيح الهوية

```text
File idempotency
= SHA-256(file bytes)

Observation fingerprint
= SHA-256(contract ID + length-prefixed canonical header/value pairs)

Source exposure key
= source_profile + normalized_agent + CVE + normalized_product

Case candidate key
= source_profile + normalized_agent + CVE
```

`Detected_At` لا تدخل في Exposure key كي تبقى المشاهدات المتكررة مرتبطة بالتعرض
نفسه، لكنها تدخل في Observation fingerprint كي نحافظ على التاريخ.

ترتيب الأعمدة لا يغير Observation fingerprint. توضع الأعمدة الثمانية الدلالية
بالترتيب الثابت للعقد، ثم الأعمدة الإضافية مرتبة حسب الاسم. الاسم والقيمة يدخلان
كـlength-prefixed UTF-8 لمنع التباس الحدود بين الحقول.

## نتيجة فحص الملف المرجعي

- الحجم: `11,193,882` bytes.
- SHA-256: `e7ff8e1ff923b3578a7a8c92e85f9c3c7674e283b3187a83377bf8b0a4d6d37d`.
- الصفوف المنطقية: `10,001` إضافة إلى header.
- جميع الصفوف بعرض 8 أعمدة؛ لا توجد صفوف malformed.
- لا توجد قيم فارغة في النسخة الحالية.
- جميع CVE والتواريخ صالحة بنيوياً.
- `5` Agents، و`2,265` CVE، و`221` منتجاً.
- `7,521` مفتاح Case مرشح من Agent+CVE.
- `9,090` مفتاح Exposure من Agent+CVE+Product.
- لا توجد صفوف متطابقة تماماً.
- توجد `910` مجموعات Exposure مكررة زمنياً، بإجمالي `911` مشاهدة إضافية.
- توجد `475` Case مرتبطة بأكثر من منتج، والحد الأعلى `27` منتجاً لحالة واحدة.
- `1,518` صفاً (`15.2%`) تحمل Severity بقيمة `-` وتُعامل كـUNKNOWN.
- توجد أوصاف تحتوي أسطراً داخل الخلية؛ لذلك يمنع تحليل الملف بأسلوب line-by-line.
- المدى الزمني من 2026-01-18 إلى 2026-07-15، ما يجعل الملف Observation Export
  متعدد الأزمنة، لا Snapshot ذات cutoff واحدة يمكن إثبات اكتمالها.

## القيود الدلالية

الملف لا يحتوي:

- Wazuh Agent ID ثابتاً.
- Package version أوarchitecture.
- Agent status أوinventory freshness.
- Snapshot ID أوgenerated-at موحداً.
- Finding status أوresolved-at.
- CVSS vector/score.

لذلك يسمح V1 بـpositive ingestion وdeduplication وCase tracking، لكنه يمنع:

- Auto-merge قوي للأصول.
- إثبات package remediation.
- استنتاج الغياب.
- Technical auto-closure.
- حساب coverage الحقيقي.

يمكن إضافة هذه الحقول لاحقاً كأعمدة اختيارية في V2 من دون كسر V1.
