#!/usr/bin/env python3
from pathlib import Path


def require(text: str, needle: str, message: str) -> None:
    if needle not in text:
        raise AssertionError(message)


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    runtime_path = root / "src/main/java/io/rbvm/postgres/FindingContextAssociationRuntime.java"
    factory_path = root / "src/main/java/io/rbvm/postgres/CanonicalProjectionFactory.java"
    self_test_path = root / "src/test/java/io/rbvm/postgres/FindingContextAssociationRuntimeSelfTest.java"

    runtime = runtime_path.read_text(encoding="utf-8")
    factory = factory_path.read_text(encoding="utf-8")
    self_test = self_test_path.read_text(encoding="utf-8")

    require(runtime, "REQUIRED_SCHEMA_VERSION = 21", "Finding-context runtime must remain gated on schema V21")
    require(runtime, "reachabilityScopeLinks.isPresent() != businessServiceLinks.isPresent()",
            "Finding-context runtime must reject partial capability activation")
    require(runtime, "PostgresFindingReachabilityScopeLinkRegistry", "Reachability registry runtime wiring is missing")
    require(runtime, "PostgresFindingBusinessServiceLinkRegistry", "Business-service registry runtime wiring is missing")

    require(factory, "FindingContextAssociationRuntime findingContextAssociations =",
            "Canonical runtime factory must own one paired finding-context capability bundle")
    require(factory, "FindingContextAssociationRuntime.forSchema(",
            "Canonical runtime factory must construct the V21 finding-context capability")
    require(factory, "FindingContextAssociationRuntime findingContextAssociations",
            "RuntimeComponents must expose the paired finding-context capability")
    require(factory, "FindingContextAssociationRuntime.disabled()",
            "Backward-compatible RuntimeComponents constructors must default the new capability to disabled")

    require(self_test, "forSchema(neverOpen, 20)", "Runtime self-test must prove pre-V21 stays disabled")
    require(self_test, "forSchema(neverOpen, 21)", "Runtime self-test must prove V21 activation")
    require(self_test, "partialRejected", "Runtime self-test must prove partial capability rejection")

    forbidden = ("AUTO_LINK", "INFERRED_LINK", "riskScore", "priorityScore", "sla")
    combined = runtime + factory
    for token in forbidden:
        if token in combined:
            raise AssertionError(f"Finding-context runtime must not introduce automatic/scoring semantics: {token}")

    print("Finding context runtime structural verification: PASS")


if __name__ == "__main__":
    main()
