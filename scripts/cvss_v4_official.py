#!/usr/bin/env python3
"""Dependency-free CVSS v4.0 scorer.

This is a Python port of the FIRST CVSS v4.0 reference calculator scoring
algorithm and MacroVector lookup data.

Reference implementation:
https://github.com/FIRSTdotorg/cvss-v4-calculator

CVSS is owned by FIRST.Org, Inc. and used by permission.
Reference calculator code/data: Copyright FIRST, Red Hat, and contributors.
SPDX-License-Identifier: BSD-2-Clause
"""

import itertools
import math

METRIC_ORDER = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "AT": ("N", "P"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "P", "A"),
    "VC": ("H", "L", "N"),
    "VI": ("H", "L", "N"),
    "VA": ("H", "L", "N"),
    "SC": ("H", "L", "N"),
    "SI": ("H", "L", "N"),
    "SA": ("H", "L", "N"),
    "E": ("X", "A", "P", "U"),
    "CR": ("X", "H", "M", "L"),
    "IR": ("X", "H", "M", "L"),
    "AR": ("X", "H", "M", "L"),
    "MAV": ("X", "N", "A", "L", "P"),
    "MAC": ("X", "L", "H"),
    "MAT": ("X", "N", "P"),
    "MPR": ("X", "N", "L", "H"),
    "MUI": ("X", "N", "P", "A"),
    "MVC": ("X", "H", "L", "N"),
    "MVI": ("X", "H", "L", "N"),
    "MVA": ("X", "H", "L", "N"),
    "MSC": ("X", "H", "L", "N"),
    "MSI": ("X", "S", "H", "L", "N"),
    "MSA": ("X", "S", "H", "L", "N"),
    "S": ("X", "N", "P"),
    "AU": ("X", "N", "Y"),
    "R": ("X", "A", "U", "I"),
    "V": ("X", "D", "C"),
    "RE": ("X", "L", "M", "H"),
    "U": ("X", "Clear", "Green", "Amber", "Red"),
}
BASE_METRICS = tuple(list(METRIC_ORDER)[:11])
ENV_METRICS = tuple(list(METRIC_ORDER)[12:26])

CVSS_LOOKUP = {
    "000000": 10, "000001": 9.9, "000010": 9.8, "000011": 9.5, "000020": 9.5, "000021": 9.2,
    "000100": 10, "000101": 9.6, "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1,
    "000200": 9.3, "000201": 9, "000210": 8.9, "000211": 8, "000220": 8.1, "000221": 6.8,
    "001000": 9.8, "001001": 9.5, "001010": 9.5, "001011": 9.2, "001020": 9, "001021": 8.4,
    "001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1, "001120": 8.1, "001121": 6.5,
    "001200": 8.8, "001201": 8, "001210": 7.8, "001211": 7, "001220": 6.9, "001221": 4.8,
    "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9, "002111": 6.9, "002121": 5,
    "002201": 6.9, "002211": 5.5, "002221": 2.7,
    "010000": 9.9, "010001": 9.7, "010010": 9.5, "010011": 9.2, "010020": 9.2, "010021": 8.5,
    "010100": 9.5, "010101": 9.1, "010110": 9, "010111": 8.3, "010120": 8.4, "010121": 7.1,
    "010200": 9.2, "010201": 8.1, "010210": 8.2, "010211": 7.1, "010220": 7.2, "010221": 5.3,
    "011000": 9.5, "011001": 9.3, "011010": 9.2, "011011": 8.5, "011020": 8.5, "011021": 7.3,
    "011100": 9.2, "011101": 8.2, "011110": 8, "011111": 7.2, "011120": 7, "011121": 5.9,
    "011200": 8.4, "011201": 7, "011210": 7.1, "011211": 5.2, "011220": 5, "011221": 3,
    "012001": 8.6, "012011": 7.5, "012021": 5.2, "012101": 7.1, "012111": 5.2, "012121": 2.9,
    "012201": 6.3, "012211": 2.9, "012221": 1.7,
    "100000": 9.8, "100001": 9.5, "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1,
    "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4, "100120": 7.7, "100121": 6.4,
    "100200": 8.7, "100201": 7.5, "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9,
    "101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7, "101020": 7.6, "101021": 6.7,
    "101100": 8.6, "101101": 7.6, "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5,
    "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2, "101220": 5.2, "101221": 2.5,
    "102001": 8.3, "102011": 7, "102021": 5.4, "102101": 6.5, "102111": 5.8, "102121": 2.6,
    "102201": 5.3, "102211": 2.1, "102221": 1.3,
    "110000": 9.5, "110001": 9, "110010": 8.8, "110011": 7.6, "110020": 7.6, "110021": 7,
    "110100": 9, "110101": 7.7, "110110": 7.5, "110111": 6.2, "110120": 6.1, "110121": 5.3,
    "110200": 7.7, "110201": 6.6, "110210": 6.8, "110211": 5.9, "110220": 5.2, "110221": 3,
    "111000": 8.9, "111001": 7.8, "111010": 7.6, "111011": 6.7, "111020": 6.2, "111021": 5.8,
    "111100": 7.4, "111101": 5.9, "111110": 5.7, "111111": 5.7, "111120": 4.7, "111121": 2.3,
    "111200": 6.1, "111201": 5.2, "111210": 5.7, "111211": 2.9, "111220": 2.4, "111221": 1.6,
    "112001": 7.1, "112011": 5.9, "112021": 3, "112101": 5.8, "112111": 2.6, "112121": 1.5,
    "112201": 2.3, "112211": 1.3, "112221": 0.6,
    "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2, "200020": 7.5, "200021": 5.8,
    "200100": 8.6, "200101": 7.4, "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4,
    "200200": 7, "200201": 5.4, "200210": 5.2, "200211": 4, "200220": 4, "200221": 2.2,
    "201000": 8.5, "201001": 7.5, "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1,
    "201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1, "201120": 4.6, "201121": 1.9,
    "201200": 5.3, "201201": 3.6, "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
    "202001": 6.4, "202011": 5.1, "202021": 2, "202101": 4.7, "202111": 2.1, "202121": 1.1,
    "202201": 2.4, "202211": 0.9, "202221": 0.4,
    "210000": 8.8, "210001": 7.5, "210010": 7.3, "210011": 5.3, "210020": 6, "210021": 5,
    "210100": 7.3, "210101": 5.5, "210110": 5.9, "210111": 4, "210120": 4.1, "210121": 2,
    "210200": 5.4, "210201": 4.3, "210210": 4.5, "210211": 2.2, "210220": 2, "210221": 1.1,
    "211000": 7.5, "211001": 5.5, "211010": 5.8, "211011": 4.5, "211020": 4, "211021": 2.1,
    "211100": 6.1, "211101": 5.1, "211110": 4.8, "211111": 1.8, "211120": 2, "211121": 0.9,
    "211200": 4.6, "211201": 1.8, "211210": 1.7, "211211": 0.7, "211220": 0.8, "211221": 0.2,
    "212001": 5.3, "212011": 2.4, "212021": 1.4, "212101": 2.4, "212111": 1.2, "212121": 0.5,
    "212201": 1, "212211": 0.3, "212221": 0.1,
}

MAX_SEVERITY = {
    "eq1": {0: 1, 1: 4, 2: 5},
    "eq2": {0: 1, 1: 2},
    "eq3eq6": {0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}},
    "eq4": {0: 6, 1: 5, 2: 4},
    "eq5": {0: 1, 1: 1, 2: 1},
}

MAX_COMPOSED = {
    "eq1": {"0": ("AV:N/PR:N/UI:N/",), "1": ("AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"), "2": ("AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/")},
    "eq2": {"0": ("AC:L/AT:N/",), "1": ("AC:H/AT:N/", "AC:L/AT:P/")},
    "eq3": {
        "0": {"0": ("VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/",), "1": ("VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/")},
        "1": {
            "0": ("VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"),
            "1": ("VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"),
        },
        "2": {"1": ("VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/",)},
    },
    "eq4": {"0": ("SC:H/SI:S/SA:S/",), "1": ("SC:H/SI:H/SA:H/",), "2": ("SC:L/SI:L/SA:L/",)},
    "eq5": {"0": ("E:A/",), "1": ("E:P/",), "2": ("E:U/",)},
}

LEVELS = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}, "PR": {"N": 0.0, "L": 0.1, "H": 0.2}, "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1}, "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2}, "VI": {"H": 0.0, "L": 0.1, "N": 0.2}, "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3}, "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}, "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2}, "IR": {"H": 0.0, "M": 0.1, "L": 0.2}, "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}

class CvssV4Error(ValueError):
    pass

def parse_vector(vector):
    if not isinstance(vector, str) or not vector.startswith("CVSS:4.0/"):
        raise CvssV4Error("vector must start with CVSS:4.0/")
    fields = vector.split("/")[1:]
    if any(not field for field in fields):
        raise CvssV4Error("empty vector field")
    selected = {metric: "X" for metric in METRIC_ORDER}
    seen = set()
    last_index = -1
    order = list(METRIC_ORDER)
    for field in fields:
        if field.count(":") != 1:
            raise CvssV4Error("malformed vector field")
        metric, value = field.split(":", 1)
        if metric not in METRIC_ORDER:
            raise CvssV4Error(f"unsupported metric: {metric}")
        if metric in seen:
            raise CvssV4Error(f"duplicate metric: {metric}")
        if value not in METRIC_ORDER[metric]:
            raise CvssV4Error(f"invalid {metric} value: {value}")
        index = order.index(metric)
        if index <= last_index:
            raise CvssV4Error("metrics are not in CVSS v4.0 canonical order")
        last_index = index
        seen.add(metric)
        selected[metric] = value
    missing = [metric for metric in BASE_METRICS if metric not in seen]
    if missing:
        raise CvssV4Error("missing mandatory Base metrics: " + ",".join(missing))
    return selected, seen

def canonical_vector(selected, include_x=False):
    parts = ["CVSS:4.0"]
    for metric in METRIC_ORDER:
        value = selected.get(metric, "X")
        if include_x or value != "X":
            parts.append(f"{metric}:{value}")
    return "/".join(parts)

def metric(selected, name):
    value = selected.get(name, "X")
    if name == "E" and value == "X":
        return "A"
    if name in ("CR", "IR", "AR") and value == "X":
        return "H"
    modified = "M" + name
    if modified in selected and selected.get(modified, "X") != "X":
        return selected[modified]
    return value

def macro_vector(selected):
    av, pr, ui = metric(selected, "AV"), metric(selected, "PR"), metric(selected, "UI")
    if av == "N" and pr == "N" and ui == "N": eq1 = "0"
    elif (av == "N" or pr == "N" or ui == "N") and not (av == "N" and pr == "N" and ui == "N") and av != "P": eq1 = "1"
    else: eq1 = "2"
    eq2 = "0" if metric(selected, "AC") == "L" and metric(selected, "AT") == "N" else "1"
    vc, vi, va = metric(selected, "VC"), metric(selected, "VI"), metric(selected, "VA")
    if vc == "H" and vi == "H": eq3 = "0"
    elif vc == "H" or vi == "H" or va == "H": eq3 = "1"
    else: eq3 = "2"
    if metric(selected, "MSI") == "S" or metric(selected, "MSA") == "S": eq4 = "0"
    elif metric(selected, "SC") == "H" or metric(selected, "SI") == "H" or metric(selected, "SA") == "H": eq4 = "1"
    else: eq4 = "2"
    eq5 = {"A": "0", "P": "1", "U": "2"}[metric(selected, "E")]
    eq6 = "0" if ((metric(selected, "CR") == "H" and metric(selected, "VC") == "H") or (metric(selected, "IR") == "H" and metric(selected, "VI") == "H") or (metric(selected, "AR") == "H" and metric(selected, "VA") == "H")) else "1"
    return eq1 + eq2 + eq3 + eq4 + eq5 + eq6

def _fragment_metrics(fragment):
    result = {}
    for token in fragment.strip("/").split("/"):
        if token:
            key, value = token.split(":", 1)
            result[key] = value
    return result

def _score_distance(current, candidate, names):
    return sum(LEVELS[name][metric(current, name)] - LEVELS[name][candidate[name]] for name in names)

def _available_distance(value, lower):
    return None if lower is None else value - lower

def score(vector):
    selected, _ = parse_vector(vector)
    if all(metric(selected, name) == "N" for name in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0
    macro = macro_vector(selected)
    if macro not in CVSS_LOOKUP:
        raise CvssV4Error(f"unsupported MacroVector: {macro}")
    value = float(CVSS_LOOKUP[macro])
    eq1, eq2, eq3, eq4, eq5, eq6 = [int(x) for x in macro]
    eq1_lower = f"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}"
    eq2_lower = f"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}"
    if eq3 == 0 and eq6 == 0:
        left = CVSS_LOOKUP.get(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}")
        right = CVSS_LOOKUP.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
        lower_values = [x for x in (left, right) if x is not None]
        eq36_lower_score = max(lower_values) if lower_values else None
    elif eq3 in (0, 1) and eq6 == 1:
        eq36_lower_score = CVSS_LOOKUP.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
    elif eq3 == 1 and eq6 == 0:
        eq36_lower_score = CVSS_LOOKUP.get(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}")
    else:
        eq36_lower_score = CVSS_LOOKUP.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6 + 1}")
    eq4_lower = f"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}"
    eq5_lower = f"{eq1}{eq2}{eq3}{eq4}{eq5 + 1}{eq6}"
    max_vectors = []
    for fragments in itertools.product(MAX_COMPOSED["eq1"][str(eq1)], MAX_COMPOSED["eq2"][str(eq2)], MAX_COMPOSED["eq3"][str(eq3)][str(eq6)], MAX_COMPOSED["eq4"][str(eq4)], MAX_COMPOSED["eq5"][str(eq5)]):
        candidate = {}
        for fragment in fragments:
            candidate.update(_fragment_metrics(fragment))
        max_vectors.append(candidate)
    chosen = None
    distances = None
    for candidate in max_vectors:
        d = {
            "eq1": _score_distance(selected, candidate, ("AV", "PR", "UI")),
            "eq2": _score_distance(selected, candidate, ("AC", "AT")),
            "eq36": _score_distance(selected, candidate, ("VC", "VI", "VA", "CR", "IR", "AR")),
            "eq4": _score_distance(selected, candidate, ("SC", "SI", "SA")),
        }
        if all(x >= -1e-12 for x in d.values()):
            chosen, distances = candidate, d
            break
    if chosen is None:
        raise CvssV4Error("no applicable MacroVector maximum found")
    available = {
        "eq1": _available_distance(value, CVSS_LOOKUP.get(eq1_lower)),
        "eq2": _available_distance(value, CVSS_LOOKUP.get(eq2_lower)),
        "eq36": _available_distance(value, eq36_lower_score),
        "eq4": _available_distance(value, CVSS_LOOKUP.get(eq4_lower)),
        "eq5": _available_distance(value, CVSS_LOOKUP.get(eq5_lower)),
    }
    depths = {"eq1": MAX_SEVERITY["eq1"][eq1] * 0.1, "eq2": MAX_SEVERITY["eq2"][eq2] * 0.1, "eq36": MAX_SEVERITY["eq3eq6"][eq3][eq6] * 0.1, "eq4": MAX_SEVERITY["eq4"][eq4] * 0.1}
    normalized = []
    for name in ("eq1", "eq2", "eq36", "eq4"):
        if available[name] is not None:
            normalized.append(available[name] * (distances[name] / depths[name]))
    if available["eq5"] is not None:
        normalized.append(0.0)
    mean_distance = sum(normalized) / len(normalized) if normalized else 0.0
    result = max(0.0, min(10.0, value - mean_distance))
    return math.floor(result * 10.0 + 0.500000000001) / 10.0

def severity(score_value):
    if score_value == 0: return "NONE"
    if score_value < 4.0: return "LOW"
    if score_value < 7.0: return "MEDIUM"
    if score_value < 9.0: return "HIGH"
    return "CRITICAL"

def nomenclature(vector):
    _, seen = parse_vector(vector)
    has_threat = "E" in seen
    has_environmental = any(metric_name in seen for metric_name in ENV_METRICS)
    if has_threat and has_environmental: return "CVSS-BTE"
    if has_environmental: return "CVSS-BE"
    if has_threat: return "CVSS-BT"
    return "CVSS-B"

def score_record(vector):
    value = score(vector)
    return {"vector": vector, "score": value, "severity": severity(value), "nomenclature": nomenclature(vector), "macroVector": macro_vector(parse_vector(vector)[0])}
