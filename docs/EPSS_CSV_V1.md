# EPSS_CSV_V1

`EPSS_CSV_V1` هو عقد تبادل مستقل لدليل FIRST EPSS على مستوى CVE. الهدف منه نقل
احتمال الاستغلال المنشور من FIRST إلى حدود المنصة الكانونية بدون تحويله إلى Risk
Score أوPriority أوSLA.

## المصدر

العقد الحالي مبني حصراً من artifact تم التحقق منه بواسطة
`scripts/fetch-first-epss-snapshot.py`:

```text
FIRST_EPSS_VALIDATED_SNAPSHOT
```

والمصدر الدلالي المثبت هو:

```text
https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
```

الـbuilder لا يعيد تنزيل FIRST ولا يعيد تفسير الـfeed. هو يقبل فقط artifact من
الـsource-adapter السابق، يتحقق من بنيته وprovenance وعدّاداته، ثم يحول الـscores
الصريحة إلى CSV.

## الحقول

```text
CVE_ID
EPSS_Probability
EPSS_Percentile
EPSS_Model_Version
EPSS_Score_Date
EPSS_Source
EPSS_Observed_At
EPSS_Source_SHA256
```

المعاني:

- `CVE_ID`: هوية CVE الكانونية.
- `EPSS_Probability`: قيمة EPSS المنشورة ضمن `[0,1]`.
- `EPSS_Percentile`: الـpercentile المنشور ضمن `[0,1]`.
- `EPSS_Model_Version`: نسخة النموذج كما وردت في metadata للـFIRST feed.
- `EPSS_Score_Date`: التاريخ الذي تمثله قيم EPSS المنشورة.
- `EPSS_Source`: المصدر الرسمي المثبت.
- `EPSS_Observed_At`: وقت نجاح المنصة في acquisition والتحقق من المصدر.
- `EPSS_Source_SHA256`: SHA-256 للـcompressed source bytes نفسها.

`EPSS_Score_Date` و`EPSS_Observed_At` متعمد أن يبقيا منفصلين:

```text
score date    = source evidence time
observed at   = platform acquisition time
```

## Missing evidence

الـsource adapter يسجل CVEs المطلوبة التي لم يجد لها score في `missingCves[]`.
الـCSV contract لا يحول هذا الغياب إلى قيمة رقمية:

```text
CVE absent from validated FIRST feed
        != EPSS 0
        != no exploitation probability
        != low risk
```

لذلك `EPSS_CSV_V1` يصدر rows فقط للـCVEs التي لديها score صريح. عدم وجود row يعني
أن المنصة لا تملك EPSS evidence صالحة لهذا CVE ضمن ذلك acquisition.

لا يوجد حقل `EPSS_Status=UNKNOWN` ولا يتم إنشاء row وهمية بقيمة صفر.

## Validation

الـJava contract والـbuilder يفرضان:

- CVE بصيغة canonical صالحة؛
- probability وpercentile ضمن `[0,1]`؛
- model version صالحة ومأخوذة من الـsnapshot؛
- score date بصيغة ISO-8601 date؛
- source مطابق لمصدر FIRST المثبت؛
- observed-at بصيغة timestamp مع timezone؛
- SHA-256 صالح ومربوط بنفس source snapshot؛
- strict UTF-8 وRFC 4180 في الـCSV؛
- عدم اختراع قيم للـmissing CVEs.

## Replay وconflict

هوية row أثناء تحليل `EPSS_CSV_V1` هي:

```text
CVE_ID
+ EPSS_Source
+ EPSS_Observed_At
```

إذا تكرر نفس المفتاح بنفس المحتوى الدلالي:

```text
exact / semantic replay
→ DEDUPLICATED
```

مثلاً `0.10` و`0.1` يمثلان نفس القيمة الرقمية.

إذا حمل نفس المفتاح probability أوpercentile أوmodel/score-date/source-hash مختلفاً:

```text
→ QUARANTINED
→ CONFLICTING_EPSS_EVIDENCE_TIMESTAMP
```

وبهذا ترتيب الصفوف لا يتحول إلى winner policy ضمنية.

## بناء العقد

```bash
python3 scripts/build-first-epss-csv.py \
  first-epss-snapshot.json \
  epss.csv \
  --report epss-build.json
```

المسار المقصود:

```text
Current CVEs
    ↓
FIRST official daily bulk feed
    ↓
FIRST_EPSS_VALIDATED_SNAPSHOT
    ↓
EPSS_CSV_V1
    ↓
Canonical validation
```

## حدود المنهجية

هذا العقد لا يضيف ولا يستنتج:

```text
Priority
Risk Score
SLA
CVSS combination
KEV combination
Asset Criticality
Internet Exposure
Business Impact
```

EPSS يبقى exploitation-probability evidence مستقلاً. أي قرار RBVM لاحق يجب أن
يأتي من طبقة قرار منفصلة بعد اكتمال الـasset/environment/business context واختيار
methodology صريحة.

## المرحلة التالية

بعد تثبيت هذا العقد، increment مستقل يضيف PostgreSQL EPSS history/current views
وtransactional importer. لا يوجد في هذا العقد مسار مباشر من FIRST إلى قاعدة
البيانات.
