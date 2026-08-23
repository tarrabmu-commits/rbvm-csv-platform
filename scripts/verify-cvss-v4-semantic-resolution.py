#!/usr/bin/env python3
"""Verify provider serialization differences do not create false CVSS v4 ambiguity."""

import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

spec = importlib.util.spec_from_file_location("rbvm_csv_enrichment", SCRIPTS / "enrich-uploaded-csv.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

compact = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"
expanded = compact + "/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X"

if module.canonical_cvss4_vector(compact) != module.canonical_cvss4_vector(expanded):
    raise AssertionError("compact Base and explicit optional-X vector must be semantically equivalent")

assessments = [
    {"source": "nvd", "type": "Secondary", "vector": expanded, "baseScore": 7.10, "baseSeverity": "HIGH"},
    {"source": "cna", "type": "CNA", "vector": compact, "baseScore": "7.1", "baseSeverity": "high"},
]
groups = module.semantic_assessment_groups(assessments)
if len(groups) != 1:
    raise AssertionError(f"equivalent provider serializations produced {len(groups)} semantic groups")

columns = module.cvss_columns({
    "nvd": {"cvssV4Assessments": [assessments[0]]},
    "cveProgram": {"cvssV4Assessments": [assessments[1]]},
})
if columns.get("CVSS4_Status") != "PRESENT":
    raise AssertionError("equivalent provider assessments must resolve PRESENT")
if columns.get("CVSS4_Assessment_Count") != "2" or columns.get("CVSS4_Semantic_Assessment_Count") != "1":
    raise AssertionError("raw and semantic assessment counts are incorrect")
if columns.get("CVSS4_AV") != "N" or columns.get("CVSS4_VA") != "H":
    raise AssertionError("base metrics were not materialized from the resolved vector")
if set(columns.get("CVSS4_Source", "").split(" | ")) != {"nvd", "cna"}:
    raise AssertionError("equivalent source provenance was not preserved")

meaningful_threat = dict(assessments[1], vector=compact + "/E:P")
if len(module.semantic_assessment_groups([assessments[0], meaningful_threat])) != 2:
    raise AssertionError("meaningful Threat differences must remain ambiguous")

meaningful_environmental = dict(assessments[1], vector=compact + "/CR:H")
if len(module.semantic_assessment_groups([assessments[0], meaningful_environmental])) != 2:
    raise AssertionError("meaningful Environmental differences must remain ambiguous")

print("CVSS v4 semantic source-resolution checks: PASS")
