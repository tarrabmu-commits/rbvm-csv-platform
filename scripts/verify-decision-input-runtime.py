#!/usr/bin/env python3
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FACTORY = ROOT / "src/main/java/io/rbvm/postgres/CanonicalProjectionFactory.java"
MATERIALIZER = ROOT / "src/main/java/io/rbvm/postgres/DefaultDecisionInputSnapshotMaterializer.java"


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


def normalized(path: Path) -> str:
    return " ".join(strip_comments(path.read_text(encoding="utf-8")).split())


def main() -> None:
    factory = normalized(FACTORY)
    materializer = normalized(MATERIALIZER)

    required_factory = (
        "Optional<DecisionRuntime> decisionRuntime = Optional.empty()",
        "if (installedVersion >= 17)",
        "new PostgresDecisionMethodologyPolicyStore(connections, false)",
        "new PostgresDecisionInputSnapshotStore(connections, false)",
        "new PostgresDecisionInputSnapshotBuilder",
        "new DefaultDecisionInputSnapshotMaterializer(builder, snapshots)",
        "new PostgresDecisionInputEvidenceResolver(connections, installedVersion)",
        "Optional.of(evidenceResolver)",
        "Optional<DecisionRuntime> decisionRuntime",
        "Optional<DecisionInputEvidenceResolver> evidenceResolver",
        "this(methodologyPolicies, snapshots, materializer, Optional.empty())",
    )
    for marker in required_factory:
        if marker not in factory:
            raise AssertionError(f"Decision Input runtime factory is missing: {marker}")

    if "if (installedVersion >= 16)" in factory and "decisionRuntime = Optional.of" in factory:
        raise AssertionError("complete Decision Input runtime must not be exposed at V16")

    required_materializer = (
        "builder.build(",
        "store.install(snapshot)",
        "new DecisionInputSnapshotMaterializationResult(snapshot, installResult)",
    )
    for marker in required_materializer:
        if marker not in materializer:
            raise AssertionError(f"Decision Input materializer is missing: {marker}")

    forbidden = (
        "risk_score",
        "priority_tier",
        "sla_days",
        "max(revision)",
        "current_policy",
        "active_policy",
        "formulaengine",
    )
    lowered = (factory + " " + materializer).lower()
    for marker in forbidden:
        if marker in lowered:
            raise AssertionError(f"Decision Input runtime must not infer decision policy/output: {marker}")

    print("Decision Input runtime wiring structural checks: PASS")


if __name__ == "__main__":
    main()
