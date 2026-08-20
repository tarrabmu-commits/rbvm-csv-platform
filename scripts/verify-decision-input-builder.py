#!/usr/bin/env python3
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILDER = ROOT / "src/main/java/io/rbvm/postgres/PostgresDecisionInputSnapshotBuilder.java"


def strip_java_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


def main() -> None:
    raw = BUILDER.read_text(encoding="utf-8")
    code = strip_java_comments(raw).lower()

    required = (
        "transaction_repeatable_read",
        "decisioninputevidenceselection.select",
        "findbyrevision(methodologyrevision)",
        "rbvm.applicability_assessment",
        "rbvm.cvss_v31_base_evidence",
        "rbvm.cisa_kev_evidence",
        "rbvm.cisa_kev_catalog_snapshot",
        "rbvm.epss_evidence",
        "rbvm.epss_score_snapshot",
        "s.score_date",
        "rbvm.asset_context_evidence",
        "rbvm.asset_context_snapshot",
        "rbvm.network_reachability_evidence",
        "rbvm.network_reachability_snapshot",
        "rbvm.business_impact_evidence",
        "rbvm.business_impact_snapshot",
        "observed_at <= ?",
        "evaluated_at <= ?",
    )
    for marker in required:
        if marker not in code:
            raise AssertionError(f"Decision Input PostgreSQL builder is missing invariant: {marker}")

    forbidden = (
        "current_applicability_assessment",
        "current_cvss_v31_base_evidence",
        "current_cisa_kev_evidence",
        "current_epss_evidence",
        "current_asset_context_evidence",
        "current_network_reachability_evidence",
        "current_business_impact_evidence",
        "finding_applicability",
        "finding_cvss_v31_base_evidence",
        "finding_cisa_kev_evidence",
        "finding_epss_evidence",
        "finding_asset_context_evidence",
        "finding_network_reachability_evidence",
        "finding_business_impact_evidence",
        "base_score",
        "cvss_vector",
        "kev_status",
        "epss_probability",
        "epss_percentile",
        "business_criticality",
        "reachability_status",
        "impact_level",
        "current_severity",
        "priority_tier",
        "risk_score",
        "sla_days",
        "max(revision)",
    )
    for marker in forbidden:
        if marker in code:
            raise AssertionError(
                f"Decision Input PostgreSQL builder must not select or rank by evidence value/policy shortcut: {marker}"
            )

    print("Decision Input PostgreSQL builder structural checks: PASS")


if __name__ == "__main__":
    main()
