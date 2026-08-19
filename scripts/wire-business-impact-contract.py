#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
path = ROOT / "src/test/java/io/rbvm/csv/PlatformSelfTest.java"
text = path.read_text(encoding="utf-8")
anchor = "        NetworkReachabilityCsvContractSelfTest.main(args);\n"
addition = anchor + "        BusinessImpactCsvContractSelfTest.main(args);\n"
if "BusinessImpactCsvContractSelfTest.main(args);" not in text:
    if text.count(anchor) != 1:
        raise RuntimeError("PlatformSelfTest Reachability anchor mismatch")
    text = text.replace(anchor, addition, 1)
path.write_text(text, encoding="utf-8")
print("Business Impact contract self-test wired")
