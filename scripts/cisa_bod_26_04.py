#!/usr/bin/env python3
"""Canonical CISA BOD 26-04 remediation-priority decision table and SSVC value resolver.

This module is deliberately separate from Organizational Risk and from the frozen
RBVM_MVP_PRIORITY_POLICY_V1 Pareto benchmark. It implements only the published
CISA BOD 26-04 response-timeline decision points and canonical outcomes.

Missing or malformed evidence is represented explicitly and is never coerced to
No/Partial or any other decision-point value.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

METHOD_ID = "CISA_BOD_26_04_REMEDIATION_PRIORITY_METHOD_V1"
SOURCE_DECISION_TABLE_ID = "cisa:DT_BOD2604:1.0.0"
SOURCE_OUTCOME_GROUP_ID = "cisa:BOD2604:1.0.0"
IN_KEV_ID = "cisa:KEV:1.0.0"
PUBLICLY_EXPOSED_ID = "cisa:PE:1.0.0"
AUTOMATABLE_ID = "ssvc:A:2.0.0"
TECHNICAL_IMPACT_ID = "ssvc:TI:1.0.0"

OUTCOMES = ("FSU", "60D", "14D", "3D", "3DF")

TABLE_ROWS = (
    ("N", "N", "N", "P", "FSU"),
    ("Y", "N", "N", "P", "14D"),
    ("N", "Y", "N", "P", "60D"),
    ("N", "N", "Y", "P", "60D"),
    ("N", "N", "N", "T", "FSU"),
    ("Y", "Y", "N", "P", "14D"),
    ("Y", "N", "Y", "P", "14D"),
    ("N", "Y", "Y", "P", "14D"),
    ("Y", "N", "N", "T", "14D"),
    ("N", "Y", "N", "T", "14D"),
    ("N", "N", "Y", "T", "60D"),
    ("Y", "Y", "Y", "P", "3D"),
    ("Y", "Y", "N", "T", "3DF"),
    ("Y", "N", "Y", "T", "3DF"),
    ("N", "Y", "Y", "T", "3D"),
    ("Y", "Y", "Y", "T", "3DF"),
)

CANONICAL = {
    "methodId": METHOD_ID,
    "classification": "CISA_REMEDIATION_PRIORITY_METHOD",
    "organizationalRisk": False,
    "sourceDecisionTableId": SOURCE_DECISION_TABLE_ID,
    "sourceOutcomeGroupId": SOURCE_OUTCOME_GROUP_ID,
    "decisionPoints": [
        {"name": "InKEV", "semanticId": IN_KEV_ID, "values": ["N", "Y"]},
        {"name": "PubliclyExposed", "semanticId": PUBLICLY_EXPOSED_ID, "values": ["N", "Y"]},
        {"name": "Automatable", "semanticId": AUTOMATABLE_ID, "values": ["N", "Y"]},
        {"name": "TechnicalImpact", "semanticId": TECHNICAL_IMPACT_ID, "values": ["P", "T"]},
    ],
    "outcomes": list(OUTCOMES),
    "missingEvidencePolicy": "INCOMPLETE; DO_NOT_COERCE_TO_NO",
    "table": [
        {
            "inKev": in_kev,
            "publiclyExposed": publicly_exposed,
            "automatable": automatable,
            "technicalImpact": technical_impact,
            "outcome": outcome,
        }
        for in_kev, publicly_exposed, automatable, technical_impact, outcome in TABLE_ROWS
    ],
}

CANONICAL_JSON = json.dumps(CANONICAL, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
METHOD_SHA256 = hashlib.sha256(CANONICAL_JSON.encode("utf-8")).hexdigest()
EXPECTED_METHOD_SHA256 = "64066ae687fd98c6db48fa224316446dc579737ff6c16321f155de69c5f0e9ff"
if METHOD_SHA256 != EXPECTED_METHOD_SHA256:
    raise RuntimeError("CISA BOD 26-04 canonical decision table drift")

_TABLE = {
    (in_kev, publicly_exposed, automatable, technical_impact): outcome
    for in_kev, publicly_exposed, automatable, technical_impact, outcome in TABLE_ROWS
}

UNRESOLVED_TOKENS = frozenset({"unknown", "missing", "incomplete"})


@dataclass(frozen=True)
class ResolvedValue:
    """One normalized BOD decision-point value without imputation."""

    status: str
    value: str | None
    raw: str
    semantic_id: str
    blocker: str | None

    @property
    def present(self) -> bool:
        return self.status == "PRESENT"


def _raw(value: object) -> str:
    return str(value or "").strip()


def _resolve(value: object, semantic_id: str, aliases: dict[str, str], missing: str, invalid: str) -> ResolvedValue:
    raw = _raw(value)
    if not raw or raw.casefold() in UNRESOLVED_TOKENS:
        return ResolvedValue("MISSING", None, raw, semantic_id, missing)
    canonical = aliases.get(raw.casefold())
    if canonical is None:
        return ResolvedValue("INVALID", None, raw, semantic_id, invalid)
    return ResolvedValue("PRESENT", canonical, raw, semantic_id, None)


def resolve_in_kev(value: object) -> ResolvedValue:
    """Resolve validated KEV membership evidence to cisa:KEV:1.0.0 Y/N.

    This function does not decide whether catalog absence is safe evidence of
    NOT_LISTED. The caller must provide a validated KEV membership state.
    """
    return _resolve(
        value,
        IN_KEV_ID,
        {
            "y": "Y", "yes": "Y", "true": "Y", "1": "Y", "listed": "Y",
            "n": "N", "no": "N", "false": "N", "0": "N", "not_listed": "N", "not listed": "N",
        },
        "IN_KEV_MISSING",
        "IN_KEV_INVALID",
    )


def resolve_publicly_exposed(value: object) -> ResolvedValue:
    """Resolve explicit customer cisa:PE:1.0.0 evidence.

    Callers must not pass the legacy customer ``internetFacing`` field as an
    implicit substitute. Publicly Exposed requires its own explicit evidence.
    """
    return _resolve(
        value,
        PUBLICLY_EXPOSED_ID,
        {"y": "Y", "yes": "Y", "true": "Y", "1": "Y", "n": "N", "no": "N", "false": "N", "0": "N"},
        "PUBLICLY_EXPOSED_MISSING",
        "PUBLICLY_EXPOSED_INVALID",
    )


def resolve_automatable(value: object) -> ResolvedValue:
    """Resolve CISA Vulnrichment Automatable to ssvc:A:2.0.0 Y/N."""
    return _resolve(
        value,
        AUTOMATABLE_ID,
        {"y": "Y", "yes": "Y", "true": "Y", "n": "N", "no": "N", "false": "N"},
        "AUTOMATABLE_MISSING",
        "AUTOMATABLE_INVALID",
    )


def resolve_technical_impact(value: object) -> ResolvedValue:
    """Resolve CISA Vulnrichment Technical Impact to ssvc:TI:1.0.0 P/T."""
    return _resolve(
        value,
        TECHNICAL_IMPACT_ID,
        {"p": "P", "partial": "P", "t": "T", "total": "T"},
        "TECHNICAL_IMPACT_MISSING",
        "TECHNICAL_IMPACT_INVALID",
    )


def resolve_cisa_ssvc(automatable: object, technical_impact: object) -> tuple[ResolvedValue, ResolvedValue]:
    """Resolve exactly the two SSVC decision points consumed by BOD 26-04.

    Generic SSVC Exploitation is intentionally not accepted because BOD 26-04
    uses CISA KEV membership as its exploitation decision point.
    """
    return resolve_automatable(automatable), resolve_technical_impact(technical_impact)


def lookup(in_kev: str, publicly_exposed: str, automatable: str, technical_impact: str) -> str:
    """Look up one complete canonical BOD decision vector.

    Missing/unknown handling belongs to the future BOD input-snapshot/decision
    engine. This low-level table function rejects incomplete or invalid values.
    """
    key = (in_kev, publicly_exposed, automatable, technical_impact)
    try:
        return _TABLE[key]
    except KeyError as error:
        raise ValueError(f"invalid/incomplete CISA BOD 26-04 decision vector: {key!r}") from error
