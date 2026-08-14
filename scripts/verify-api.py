#!/usr/bin/env python3
from pathlib import Path
import sys

import yaml


class StrictLoader(yaml.SafeLoader):
    pass


def construct_unique_mapping(loader, node, deep=False):
    output = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in output:
            raise AssertionError(
                f"OpenAPI contains duplicate key {key!r} at line {key_node.start_mark.line + 1}"
            )
        output[key] = loader.construct_object(value_node, deep=deep)
    return output


StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_mapping,
)


def walk(value):
    yield value
    if isinstance(value, dict):
        for nested in value.values():
            yield from walk(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from walk(nested)


def resolve_local_ref(document, reference):
    if not reference.startswith("#/"):
        return
    value = document
    for segment in reference[2:].split("/"):
        segment = segment.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or segment not in value:
            raise AssertionError(f"OpenAPI reference does not resolve: {reference}")
        value = value[segment]


def main():
    root = Path(__file__).resolve().parent.parent
    path = root / "api/openapi.yaml"
    document = yaml.load(path.read_text(encoding="utf-8"), Loader=StrictLoader)

    if document.get("openapi") != "3.1.1":
        raise AssertionError("OpenAPI document must declare 3.1.1")
    if document.get("info", {}).get("version") != "0.11.0":
        raise AssertionError("OpenAPI info.version must match Increment 11")

    bearer = document.get("components", {}).get("securitySchemes", {}).get("bearerAuth", {})
    if bearer.get("type") != "http" or bearer.get("scheme") != "bearer":
        raise AssertionError("OpenAPI must declare bearer API-key authentication")
    if document.get("security") != [{"bearerAuth": []}]:
        raise AssertionError("OpenAPI must protect operations by default")
    responses = document.get("components", {}).get("responses", {})
    for name in {"AuthenticationRequired", "InsufficientRole", "RateLimited"}:
        if name not in responses:
            raise AssertionError(f"OpenAPI lacks reusable security response {name}")

    operation_ids = []
    for path_item in document.get("paths", {}).values():
        for method, operation in path_item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            operation_id = operation.get("operationId")
            if not operation_id:
                raise AssertionError(f"OpenAPI {method.upper()} operation lacks operationId")
            operation_ids.append(operation_id)
    if len(operation_ids) != len(set(operation_ids)):
        raise AssertionError("OpenAPI operationId values must be unique")

    for item in walk(document):
        if isinstance(item, dict) and "$ref" in item:
            resolve_local_ref(document, item["$ref"])

    required_paths = {
        "/csv-imports",
        "/csv-imports/{importId}",
        "/csv-imports/{importId}/confirm",
        "/catalog/summary",
        "/cases",
        "/cases/{caseId}",
        "/cases/{caseId}/actions",
    }
    missing = required_paths - set(document.get("paths", {}))
    if missing:
        raise AssertionError(f"OpenAPI is missing paths: {sorted(missing)}")

    schemas = document["components"]["schemas"]
    statuses = schemas["CaseView"]["properties"]["status"]["enum"]
    if set(statuses) != {
        "OPEN", "SOURCE_RESOLVED", "ACCEPTED_RISK", "FALSE_POSITIVE", "CLOSED_MANUAL"
    }:
        raise AssertionError("Case workflow statuses are incomplete")

    print("OpenAPI structural checks: PASS")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(error, file=sys.stderr)
        raise
