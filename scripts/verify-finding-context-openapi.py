#!/usr/bin/env python3
from pathlib import Path
import yaml


class StrictLoader(yaml.SafeLoader):
    pass


def construct_unique_mapping(loader, node, deep=False):
    output = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in output:
            raise AssertionError(
                f"Finding-context OpenAPI contains duplicate key {key!r} "
                f"at line {key_node.start_mark.line + 1}"
            )
        output[key] = loader.construct_object(value_node, deep=deep)
    return output


StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_mapping,
)


EXPECTED_PATHS = {
    "/findings/{findingId}/reachability-links": {"get"},
    "/findings/{findingId}/reachability-links/current": {"get", "post"},
    "/findings/{findingId}/reachability-links/revisions": {"get"},
    "/findings/{findingId}/business-service-links": {"get"},
    "/findings/{findingId}/business-service-links/current": {"get", "post"},
    "/findings/{findingId}/business-service-links/revisions": {"get"},
}


def resolve_local_ref(document, reference):
    if not reference.startswith("#/"):
        raise AssertionError(f"Finding-context fragment must use local refs only: {reference}")
    value = document
    for segment in reference[2:].split("/"):
        segment = segment.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or segment not in value:
            raise AssertionError(f"Finding-context OpenAPI reference does not resolve: {reference}")
        value = value[segment]
    return value


def walk(value):
    yield value
    if isinstance(value, dict):
        for nested in value.values():
            yield from walk(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from walk(nested)


def parameter_names(document, operation):
    names = set()
    for parameter in operation.get("parameters", []):
        if "$ref" in parameter:
            parameter = resolve_local_ref(document, parameter["$ref"])
        names.add((parameter.get("in"), parameter.get("name")))
    return names


def main():
    root = Path(__file__).resolve().parent.parent
    spec_path = root / "api/finding-context-association.openapi.yaml"
    router_path = root / "src/main/java/io/rbvm/csv/FindingContextAssociationHttpRouter.java"
    reachability_api_path = root / "src/main/java/io/rbvm/csv/FindingReachabilityScopeLinkApi.java"
    business_api_path = root / "src/main/java/io/rbvm/csv/FindingBusinessServiceLinkApi.java"

    document = yaml.load(spec_path.read_text(encoding="utf-8"), Loader=StrictLoader)
    router = router_path.read_text(encoding="utf-8")
    reachability_api = reachability_api_path.read_text(encoding="utf-8")
    business_api = business_api_path.read_text(encoding="utf-8")

    if document.get("openapi") != "3.1.2":
        raise AssertionError("Finding-context OpenAPI fragment must declare 3.1.2")
    if document.get("info", {}).get("version") != "0.23.2":
        raise AssertionError("Finding-context fragment version must match release 0.23.2")
    if document.get("security") != [{"bearerAuth": []}]:
        raise AssertionError("Finding-context fragment must require bearer authentication by default")

    paths = document.get("paths", {})
    if set(paths) != set(EXPECTED_PATHS):
        raise AssertionError(
            f"Finding-context OpenAPI path set drifted: {sorted(set(paths) ^ set(EXPECTED_PATHS))}"
        )
    operation_ids = []
    for path, expected_methods in EXPECTED_PATHS.items():
        item = paths[path]
        methods = {key for key in item if key in {"get", "post", "put", "patch", "delete"}}
        if methods != expected_methods:
            raise AssertionError(f"Unexpected methods for {path}: {sorted(methods)}")
        if item.get("parameters") != [{"$ref": "#/components/parameters/FindingId"}]:
            raise AssertionError(f"{path} must carry the canonical FindingId path parameter")
        for method in expected_methods:
            operation = item[method]
            operation_id = operation.get("operationId")
            if not operation_id:
                raise AssertionError(f"{method.upper()} {path} lacks operationId")
            operation_ids.append(operation_id)
            responses = operation.get("responses", {})
            for status in ("200", "401", "429", "503"):
                if status not in responses:
                    raise AssertionError(f"{method.upper()} {path} lacks response {status}")
            if method == "post":
                for status in ("400", "403", "404", "412", "413", "415", "422", "428"):
                    if status not in responses:
                        raise AssertionError(f"POST {path} lacks response {status}")
                params = parameter_names(document, operation)
                query_params = {name for location, name in params if location == "query"}
                if query_params:
                    raise AssertionError(
                        f"POST {path} must not expose query-owned mutation targets: {sorted(query_params)}"
                    )
                if ("header", "If-Match") not in params:
                    raise AssertionError(f"POST {path} must require If-Match")
                request_schema = operation["requestBody"]["content"]["application/json"]["schema"]
                request_schema = resolve_local_ref(document, request_schema["$ref"])
                if "changedBy" in request_schema.get("properties", {}):
                    raise AssertionError(f"POST {path} must not accept client-supplied changedBy")

    if len(operation_ids) != len(set(operation_ids)):
        raise AssertionError("Finding-context operationId values must be unique")

    reachability_get = paths["/findings/{findingId}/reachability-links/current"]["get"]
    reachability_query = parameter_names(document, reachability_get)
    for name in ("originScope", "originLabel", "transportProtocol", "targetPort"):
        if ("query", name) not in reachability_query:
            raise AssertionError(f"Reachability current GET lacks target query parameter {name}")

    business_get = paths["/findings/{findingId}/business-service-links/current"]["get"]
    if ("query", "businessService") not in parameter_names(document, business_get):
        raise AssertionError("Business-service current GET lacks businessService target query")

    for item in walk(document):
        if isinstance(item, dict) and "$ref" in item:
            resolve_local_ref(document, item["$ref"])

    schemas = document["components"]["schemas"]
    for name in (
        "AssociationState",
        "FindingReachabilityLinkEvent",
        "FindingReachabilityLinkCurrent",
        "FindingReachabilityLinkMutationCurrent",
        "FindingReachabilityLinkPage",
        "FindingReachabilityLinkHistoryPage",
        "FindingReachabilityLinkRevisionRequest",
        "FindingBusinessServiceLinkEvent",
        "FindingBusinessServiceLinkCurrent",
        "FindingBusinessServiceLinkPage",
        "FindingBusinessServiceLinkHistoryPage",
        "FindingBusinessServiceLinkRevisionRequest",
    ):
        if name not in schemas:
            raise AssertionError(f"Finding-context fragment lacks schema {name}")

    if schemas["AssociationState"].get("enum") != ["NEVER_ASSESSED", "LINKED", "UNLINKED"]:
        raise AssertionError("AssociationState must preserve NEVER_ASSESSED vs explicit UNLINKED")
    for event_name in ("FindingReachabilityLinkEvent", "FindingBusinessServiceLinkEvent"):
        event = schemas[event_name]
        properties = event.get("properties", {})
        if properties.get("linkMethod", {}).get("const") != "CUSTOMER_CONFIRMED":
            raise AssertionError(f"{event_name} must remain CUSTOMER_CONFIRMED only")
        for field in ("evidenceSha256", "changedBy", "recordedAt"):
            if field not in event.get("required", []):
                raise AssertionError(f"{event_name} must retain immutable audit field {field}")

    # Cross-check the published shape against implementation-owned route and body/query contracts.
    for token in (
        "reachability-links",
        "business-service-links",
        'if ("POST".equals(method)) return ApiRole.OPERATOR;',
        "principal.actorId()",
    ):
        if token not in router:
            raise AssertionError(f"Router contract no longer supports documented token: {token}")
    for token in (
        '"originScope", "originLabel", "transportProtocol", "targetPort"',
        '"linkStatus", "originScope", "originLabel", "transportProtocol"',
        'body.put("associationState", current == null ? "NEVER_ASSESSED"',
        'body.put("target", target.view())',
    ):
        if token not in reachability_api:
            raise AssertionError(f"Reachability API drifted from fragment contract: {token}")
    for token in (
        'Set.of("businessService")',
        '"linkStatus", "businessService", "changeNote"',
        'body.put("associationState", current == null ? "NEVER_ASSESSED"',
        'body.put("businessService", service)',
    ):
        if token not in business_api:
            raise AssertionError(f"Business-service API drifted from fragment contract: {token}")

    forbidden = ("AUTO_LINK", "INFERRED_LINK", "riskScore", "priorityScore", "slaPolicy")
    text = spec_path.read_text(encoding="utf-8")
    for token in forbidden:
        if token in text:
            raise AssertionError(f"Finding-context fragment introduces forbidden semantics: {token}")

    print("Finding context OpenAPI fragment verification: PASS")


if __name__ == "__main__":
    main()
