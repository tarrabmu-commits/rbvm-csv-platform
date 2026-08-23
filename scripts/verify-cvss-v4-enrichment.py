#!/usr/bin/env python3
"""Verify CSV enrichment wiring for official CVSS v4 B/BT calculation."""

import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("enrich_uploaded_csv", ROOT / "scripts" / "enrich-uploaded-csv.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

BASE = {
    "CVSS4_Status": "PRESENT", "CVSS4_Base_Score": "9.3", "CVSS4_E": "",
    "CVSS4_AV": "N", "CVSS4_AC": "L", "CVSS4_AT": "N", "CVSS4_PR": "N", "CVSS4_UI": "N",
    "CVSS4_VC": "H", "CVSS4_VI": "H", "CVSS4_VA": "H", "CVSS4_SC": "N", "CVSS4_SI": "N", "CVSS4_SA": "N",
    "KEV_Listed": "true",
}
result = module.calculated_cvss_columns(BASE)
if result["CVSS4_Calculated_Status"] != "CALCULATED":
    raise AssertionError(result)
if result["CVSS4_Calculated_Nomenclature"] != "CVSS-BT" or result["CVSS4_Calculated_Score"] != "9.3":
    raise AssertionError("KEV-attested Threat E was not scored as CVSS-BT")
if result["CVSS4_Threat_E_Resolution"] != "KEV_ATTESTED" or not result["CVSS4_Calculated_Vector"].endswith("/E:A"):
    raise AssertionError("KEV must resolve E:A explicitly")
if result["CVSS4_Base_Score_Validation"] != "MATCH" or result["CVSS4_Base_Score_Calculated"] != "9.3":
    raise AssertionError("published Base score validation failed")

threat = dict(BASE)
threat.update({"CVSS4_Base_Score": "7.7", "CVSS4_AT": "P", "CVSS4_UI": "P", "CVSS4_E": "U", "KEV_Listed": "false"})
result = module.calculated_cvss_columns(threat)
if result["CVSS4_Calculated_Score"] != "5.2" or result["CVSS4_Calculated_Nomenclature"] != "CVSS-BT":
    raise AssertionError("published E:U did not produce the FIRST example BT score")

conflict = dict(threat)
conflict["KEV_Listed"] = "true"
result = module.calculated_cvss_columns(conflict)
if result["CVSS4_Calculated_Status"] != "AMBIGUOUS_THREAT_CONFLICT" or result["CVSS4_Calculated_Score"]:
    raise AssertionError("published E:U conflicting with KEV must not be silently overridden")

missing = module.calculated_cvss_columns({"CVSS4_Status": "MISSING"})
if missing["CVSS4_Calculated_Status"] != "MISSING" or missing["CVSS4_Calculated_Score"]:
    raise AssertionError("missing CVSS v4 Base must remain missing")

print("CVSS v4 CSV-enrichment scoring checks: PASS")
