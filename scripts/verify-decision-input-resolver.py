#!/usr/bin/env python3
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESOLVER = ROOT / "src/main/java/io/rbvm/postgres/PostgresDecisionInputEvidenceResolver.java"


def strip_java_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


def main() -> None:
    raw = RESOLVER.read_text(encoding="utf-8")
    code = strip_java_comments(raw).lower()

    required = (
        "implements decisioninputevidenceresolver",
        "transaction_repeatable_read",
        "setreadonly(true)",
        "rbvm.applicability_assessment",
        "rbvm.cvss_v31_base_evidence",
        "rbvm.cisa_kev_evidence",
        "rbvm.cisa_kev_catalog_snapshot",
        "rbvm.epss_evidence",
        "rbvm.epss_score_snapshot",
        "rbvm.asset_context_evidence",
        "rbvm.asset_context_snapshot",
        "rbvm.network_reachability_evidence",
        "rbvm.network_reachability_snapshot",
        "rbvm.business_impact_evidence",
        "rbvm.business_impact_snapshot",
        "tenant_id = ?",
        "id = ?",
        "verifyreference(reference",
        "reference.evidencesha256()",
        "reference.evidencesource()",
        "reference.observedat()",
        "new rbvmresolveddecisioninput(snapshot, resolved)",
    )
    for marker in required:
        if marker not in code:
            raise AssertionError(
                f"Decision Input PostgreSQL resolver is missing invariant: {marker}"
            )

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
        "decisioninputevidenceselection.select",
        " order by ",
        " limit 1",
        "max(",
        "min(",
        "priority_tier",
        "risk_score",
        "sla_days",
        "active_policy",
        "highest_revision",
    )
    for marker in forbidden:
        if marker in code:
            raise AssertionError(
                "Decision Input PostgreSQL resolver must dereference exact snapshot evidence only: "
                + marker
            )

    print("Decision Input PostgreSQL resolver structural checks: PASS")


if __name__ == "__main__":
    main()
