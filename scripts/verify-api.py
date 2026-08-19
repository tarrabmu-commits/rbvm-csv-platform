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
    if document.get("info", {}).get("version") != "0.14.0":
        raise AssertionError("OpenAPI info.version must match Increment 14")

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
        "/applicability-findings.csv",
        "/applicability-imports",
        "/cvss-v31-evidence",
        "/cvss-v31-imports",
        "/cisa-kev-evidence",
        "/cisa-kev-imports",
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

    health_required = set(schemas["Health"].get("required", []))
    if "cvssV31" not in health_required:
        raise AssertionError("Health schema must expose CVSS v3.1 runtime capability")
    cvss_capability = schemas.get("CvssV31Capability", {})
    if set(cvss_capability.get("required", [])) != {"importEnabled", "evidenceReadEnabled"}:
        raise AssertionError("CVSS v3.1 capability schema is incomplete")

    if "cisaKev" not in health_required:
        raise AssertionError("Health schema must expose CISA KEV runtime capability")
    kev_capability = schemas.get("CisaKevCapability", {})
    if set(kev_capability.get("required", [])) != {"importEnabled", "evidenceReadEnabled"}:
        raise AssertionError("CISA KEV capability schema is incomplete")

    kev_import = schemas.get("CisaKevImportResult", {})
    required_kev_import_fields = {
        "insertedSnapshots",
        "replayedSnapshots",
        "snapshotConflictGroups",
        "insertedEvidence",
        "replayedEvidence",
        "persistenceQuarantinedRows",
        "contractQuarantinedRows",
        "totalQuarantinedRows",
        "uniqueCves",
        "uniqueSnapshots",
    }
    if not required_kev_import_fields.issubset(set(kev_import.get("required", []))):
        raise AssertionError("CISA KEV import result schema is incomplete")
    if kev_import.get("properties", {}).get("contractId", {}).get("const") != "CISA_KEV_CSV_V1":
        raise AssertionError("CISA KEV import result must bind to CISA_KEV_CSV_V1")
    if kev_import.get("properties", {}).get("semantics", {}).get("const") != \
  "CVE_SCOPED_CISA_KEV_SNAPSHOT_MEMBERSHIP_EVIDENCE":
        raise AssertionError("CISA KEV import semantics are incorrect")

    kev_page = schemas.get("CisaKevEvidencePage", {})
    if kev_page.get("properties", {}).get("semantics", {}).get("const") != \
  "CURRENT_PER_SOURCE_CISA_KEV_SNAPSHOT_MEMBERSHIP_EVIDENCE":
        raise AssertionError("CISA KEV read semantics must remain current-per-source")
    kev_item = schemas.get("CisaKevEvidenceItem", {}).get("properties", {})
    if set(kev_item.get("kevStatus", {}).get("enum", [])) != {"LISTED", "NOT_LISTED"}:
        raise AssertionError("CISA KEV API must not persist or expose fabricated UNKNOWN rows")
    if kev_item.get("kevCatalogSha256", {}).get("pattern") != "^[a-f0-9]{64}$":
        raise AssertionError("CISA KEV API must expose snapshot SHA-256 provenance")

    applicability = schemas.get("ApplicabilityImportResult", {})
    required_applicability_fields = {
        "insertedAssessments",
        "replayedAssessments",
        "persistenceQuarantinedRows",
        "contractQuarantinedRows",
        "totalQuarantinedRows",
    }
    if not required_applicability_fields.issubset(set(applicability.get("required", []))):
        raise AssertionError("Applicability import result schema is incomplete")

    cvss_import = schemas.get("CvssV31ImportResult", {})
    required_cvss_import_fields = {
        "insertedEvidence",
        "replayedEvidence",
        "persistenceQuarantinedRows",
        "contractQuarantinedRows",
        "totalQuarantinedRows",
        "uniqueCves",
        "uniqueSources",
    }
    if not required_cvss_import_fields.issubset(set(cvss_import.get("required", []))):
        raise AssertionError("CVSS v3.1 import result schema is incomplete")
    if cvss_import.get("properties", {}).get("contractId", {}).get("const") != "CVSS_V31_CSV_V1":
        raise AssertionError("CVSS import result must bind to CVSS_V31_CSV_V1")
    if cvss_import.get("properties", {}).get("semantics", {}).get("const") != \
            "CVE_SCOPED_CVSS_V31_BASE_EVIDENCE":
        raise AssertionError("CVSS import semantics are incorrect")

    cvss_page = schemas.get("CvssV31EvidencePage", {})
    if cvss_page.get("properties", {}).get("semantics", {}).get("const") != \
            "CURRENT_PER_SOURCE_CVSS_V31_BASE_EVIDENCE":
        raise AssertionError("CVSS read semantics must remain current-per-source")
    cvss_item = schemas.get("CvssV31EvidenceItem", {}).get("properties", {})
    if cvss_item.get("cvssVersion", {}).get("const") != "3.1":
        raise AssertionError("CVSS evidence API must remain exact v3.1")
    if cvss_item.get("cvssBaseScore", {}).get("maximum") != 10:
        raise AssertionError("CVSS Base score API range is incomplete")

    exposure_properties = schemas.get("ExposureView", {}).get("properties", {})
    for field in {
        "findingId",
        "applicabilityStatus",
        "applicabilityAssessed",
        "applicabilityReason",
        "applicabilityEvidenceSource",
        "applicabilityEvaluatedAt",
    }:
        if field not in exposure_properties:
            raise AssertionError(f"ExposureView lacks applicability field {field}")

    print("OpenAPI structural checks: PASS")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(error, file=sys.stderr)
        raise
