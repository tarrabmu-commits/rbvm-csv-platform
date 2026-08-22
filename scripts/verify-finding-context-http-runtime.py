#!/usr/bin/env python3
from pathlib import Path


def require(text: str, needle: str, message: str) -> None:
    if needle not in text:
        raise AssertionError(message)


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    server = (root / "src/main/java/io/rbvm/csv/CsvPlatformServer.java").read_text(encoding="utf-8")
    router = (root / "src/main/java/io/rbvm/csv/FindingContextAssociationHttpRouter.java").read_text(encoding="utf-8")
    socket_test = (root / "src/test/java/io/rbvm/csv/CsvFindingContextAssociationHttpSelfTest.java").read_text(encoding="utf-8")

    require(server, "FindingContextAssociationRuntime findingContextAssociations",
            "CsvPlatformServer must accept the paired V21 runtime capability")
    require(server, "FindingContextAssociationHttpRouter.inNamespace(path)",
            "CsvPlatformServer must dispatch the Finding-context namespace")
    require(server, "FindingContextAssociationHttpRouter.requiredRole(exchange, method)",
            "Finding-context routes must resolve their required role before dispatch")
    require(server, "authorize(exchange, requiredRole)",
            "Finding-context routes must pass through the server authorization boundary")
    require(server, "FINDING_CONTEXT_ASSOCIATION_PERSISTENCE_UNAVAILABLE",
            "Unavailable Finding-context persistence must have an explicit 503 problem code")
    require(server, "PostgreSQL schema version 21 or newer",
            "Finding-context runtime availability message must name the V21 gate")
    require(server, 'health.put("findingContextAssociations"',
            "Health output must expose Finding-context capability state")
    require(server, "rbvm_finding_context_association_api_enabled",
            "Metrics must expose the paired Finding-context API capability")
    require(server, "runtime.findingContextAssociations()",
            "Application bootstrap must pass the V21 capability into CsvPlatformServer")

    for path in (
        "/reachability-links",
        "/reachability-links/current",
        "/reachability-links/revisions",
        "/business-service-links",
        "/business-service-links/current",
        "/business-service-links/revisions",
    ):
        require(router, path.split("/")[1], f"Router must retain association namespace for {path}")

    require(router, 'if ("GET".equals(method)) return ApiRole.VIEWER;',
            "Finding-context reads must retain VIEWER role")
    require(router, 'if ("POST".equals(method)) return ApiRole.OPERATOR;',
            "Finding-context current-state writes must retain OPERATOR role")
    require(router, "principal.actorId()",
            "Mutation audit actor must remain server-derived from AuthPrincipal")

    require(socket_test, "viewerWriteDenied.statusCode() == 403",
            "Socket test must prove VIEWER cannot mutate associations")
    require(socket_test, 'contains("\\\"changedBy\\\": \\\"finding-context-operator\\\"")',
            "Socket test must prove audit actor comes from authenticated OPERATOR")
    require(socket_test, "viewerUnavailable.statusCode() == 503",
            "Socket test must prove authenticated reads see explicit capability-unavailable 503")
    require(socket_test, "operatorUnavailable.statusCode() == 503",
            "Socket test must prove authenticated writes see explicit capability-unavailable 503")
    require(socket_test, "missing.statusCode() == 401",
            "Socket test must prove authentication happens before unavailable capability disclosure")

    forbidden = ("AUTO_LINK", "INFERRED_LINK", "riskScore", "priorityScore", "sla")
    combined = server + router
    for token in forbidden:
        if token in combined:
            raise AssertionError(f"Finding-context HTTP runtime must not introduce automatic/scoring semantics: {token}")

    print("Finding context HTTP runtime structural verification: PASS")


if __name__ == "__main__":
    main()
