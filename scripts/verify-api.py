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

    if document.get("openapi") != "3.1.2":
        raise AssertionError("OpenAPI document must declare 3.1.2")
    if document.get("info", {}).get("version") != "0.23.0":
        raise AssertionError("OpenAPI info.version must match Increment 23")

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
        "/epss-evidence",
        "/epss-imports",
        "/asset-context-evidence",
        "/asset-context-imports",
        "/network-reachability-evidence",
        "/network-reachability-imports",
        "/business-impact-evidence",
        "/business-impact-imports",
        "/managed-assets",
        "/managed-assets/{managedAssetId}",
        "/managed-assets/{managedAssetId}/revisions",
        "/scanner-assets",
        "/scanner-assets/{scannerAssetId}/managed-asset-link",
        "/scanner-assets/{scannerAssetId}/managed-asset-link/revisions",
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

    if "epss" not in health_required:
        raise AssertionError("Health schema must expose EPSS runtime capability")
    epss_capability = schemas.get("EpssCapability", {})
    if set(epss_capability.get("required", [])) != {"importEnabled", "evidenceReadEnabled"}:
        raise AssertionError("EPSS capability schema is incomplete")

    if "assetContext" not in health_required:
        raise AssertionError("Health schema must expose Asset Context runtime capability")
    asset_context_capability = schemas.get("AssetContextCapability", {})
    if set(asset_context_capability.get("required", [])) != {
        "importEnabled", "evidenceReadEnabled"
    }:
        raise AssertionError("Asset Context capability schema is incomplete")

    if "networkReachability" not in health_required:
        raise AssertionError("Health schema must expose Network Reachability runtime capability")
    reachability_capability = schemas.get("NetworkReachabilityCapability", {})
    if set(reachability_capability.get("required", [])) != {
        "importEnabled", "evidenceReadEnabled"
    }:
        raise AssertionError("Network Reachability capability schema is incomplete")

    if "businessImpact" not in health_required:
        raise AssertionError("Health schema must expose Business Impact runtime capability")
    business_impact_capability = schemas.get("BusinessImpactCapability", {})
    if set(business_impact_capability.get("required", [])) != {
        "importEnabled", "evidenceReadEnabled"
    }:
        raise AssertionError("Business Impact capability schema is incomplete")

    if "managedAssets" not in health_required:
        raise AssertionError("Health schema must expose Managed Asset runtime capability")
    managed_asset_capability = schemas.get("ManagedAssetCapability", {})
    if set(managed_asset_capability.get("required", [])) != {
        "readEnabled", "writeEnabled", "historyReadEnabled"
    }:
        raise AssertionError("Managed Asset capability schema is incomplete")

    if "scannerManagedAssetLinks" not in health_required:
        raise AssertionError("Health schema must expose scanner-managed-asset link capability")
    link_capability = schemas.get("ScannerManagedAssetLinkCapability", {})
    if set(link_capability.get("required", [])) != {
        "readEnabled", "writeEnabled", "historyReadEnabled"
    }:
        raise AssertionError("Scanner-managed-asset link capability schema is incomplete")

    link_revision = schemas.get("ScannerManagedAssetLinkRevisionRequest", {})
    if link_revision.get("additionalProperties") is not False:
        raise AssertionError("Scanner-managed-asset link revisions must reject unknown JSON fields")

    create_managed_asset = schemas.get("CreateManagedAssetRequest", {})
    append_managed_asset = schemas.get("AppendManagedAssetRevisionRequest", {})
    if create_managed_asset.get("additionalProperties") is not False:
        raise AssertionError("Managed asset create must reject unknown JSON fields")
    if append_managed_asset.get("additionalProperties") is not False:
        raise AssertionError("Managed asset revisions must reject unknown JSON fields")
    server_owned = {"changedBy", "recordedAt", "contextSource", "evidenceSha256", "revision", "id"}
    if server_owned.intersection(create_managed_asset.get("properties", {})):
        raise AssertionError("Managed asset create exposes server-owned audit fields")
    if server_owned.intersection(append_managed_asset.get("properties", {})):
        raise AssertionError("Managed asset revision exposes server-owned audit fields")
    if "customerAssetKey" in append_managed_asset.get("properties", {}):
        raise AssertionError("customerAssetKey must remain immutable after managed asset creation")
    if "lifecycleStatus" in create_managed_asset.get("properties", {}):
        raise AssertionError("Managed asset creation must force ACTIVE revision 1")
    if "lifecycleStatus" not in append_managed_asset.get("required", []):
        raise AssertionError("Managed asset revisions must state lifecycle explicitly")

    for request_name, request_schema in (
        ("create", create_managed_asset),
        ("revision", append_managed_asset),
    ):
        rules = request_schema.get("allOf", [])
        guided_rules = [
            rule for rule in rules
            if rule.get("if", {}).get("properties", {}).get("classificationMethod", {}).get("const")
            == "GUIDED"
        ]
        direct_rules = [
            rule for rule in rules
            if rule.get("if", {}).get("properties", {}).get("classificationMethod", {}).get("const")
            == "CUSTOMER_DIRECT"
        ]
        if len(guided_rules) != 1 or set(guided_rules[0].get("then", {}).get("required", [])) != {
            "guideContractId", "guideRevision"
        }:
            raise AssertionError(f"Managed asset {request_name} must require guided provenance")
        if len(direct_rules) != 1:
            raise AssertionError(f"Managed asset {request_name} must constrain direct guide metadata")
        direct_properties = direct_rules[0].get("then", {}).get("properties", {})
        if direct_properties.get("guideContractId", {}).get("type") != "null" or \
                direct_properties.get("guideRevision", {}).get("type") != "null":
            raise AssertionError(
                f"Managed asset {request_name} CUSTOMER_DIRECT must not claim guide provenance"
            )

    managed_paths = document["paths"]
    if "delete" in managed_paths["/managed-assets/{managedAssetId}"]:
        raise AssertionError("Managed assets must be retired by revision, never deleted")
    revision_post = managed_paths["/managed-assets/{managedAssetId}/revisions"]["post"]
    if_match = [p for p in revision_post.get("parameters", []) if p.get("name") == "If-Match"]
    if len(if_match) != 1 or if_match[0].get("required") is not True:
        raise AssertionError("Managed asset revision POST must require If-Match")
    if not {"412", "428"}.issubset(set(revision_post.get("responses", {}))):
        raise AssertionError("Managed asset revision POST must document 412 and 428")

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

    epss_import = schemas.get("EpssImportResult", {})
    required_epss_import_fields = {
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
    if not required_epss_import_fields.issubset(set(epss_import.get("required", []))):
        raise AssertionError("EPSS import result schema is incomplete")
    if epss_import.get("properties", {}).get("contractId", {}).get("const") != "EPSS_CSV_V1":
        raise AssertionError("EPSS import result must bind to EPSS_CSV_V1")
    if epss_import.get("properties", {}).get("semantics", {}).get("const") != \
            "CVE_SCOPED_FIRST_EPSS_PROBABILITY_EVIDENCE":
        raise AssertionError("EPSS import semantics are incorrect")

    epss_page = schemas.get("EpssEvidencePage", {})
    if epss_page.get("properties", {}).get("semantics", {}).get("const") != \
            "CURRENT_PER_SOURCE_EPSS_EXPLOITATION_PROBABILITY_EVIDENCE":
        raise AssertionError("EPSS read semantics must remain current-per-source")
    epss_item = schemas.get("EpssEvidenceItem", {}).get("properties", {})
    for probability_field in ("epssProbability", "epssPercentile"):
        probability = epss_item.get(probability_field, {})
        if probability.get("minimum") != 0 or probability.get("maximum") != 1:
            raise AssertionError(f"{probability_field} must remain bounded to [0,1]")
    if epss_item.get("epssSourceSha256", {}).get("pattern") != "^[a-f0-9]{64}$":
        raise AssertionError("EPSS API must expose exact source-byte SHA-256 provenance")
    if epss_item.get("epssScoreDate", {}).get("format") != "date":
        raise AssertionError("EPSS API must expose the FIRST score publication date")
    if epss_item.get("epssObservedAt", {}).get("format") != "date-time":
        raise AssertionError("EPSS API must preserve acquisition observation time separately")
    forbidden_epss_fields = {
        "priority", "priorityTier", "riskScore", "slaDays", "threshold", "knownExploited"
    }
    if forbidden_epss_fields.intersection(epss_item):
        raise AssertionError("Independent EPSS evidence must not contain decision-policy fields")

    asset_context_import = schemas.get("AssetContextImportResult", {})
    required_asset_context_import_fields = {
        "contractId",
        "semantics",
        "logicalRows",
        "acceptedRows",
        "insertedSnapshots",
        "replayedSnapshots",
        "snapshotConflictGroups",
        "insertedEvidence",
        "replayedEvidence",
        "contractDeduplicatedRows",
        "persistenceQuarantinedRows",
        "contractQuarantinedRows",
        "totalDeduplicatedRows",
        "totalQuarantinedRows",
        "environmentDistribution",
        "criticalityDistribution",
        "contractIssues",
        "persistenceIssues",
    }
    if not required_asset_context_import_fields.issubset(
            set(asset_context_import.get("required", []))
    ):
        raise AssertionError("Asset Context import result schema is incomplete")
    asset_context_import_properties = asset_context_import.get("properties", {})
    if asset_context_import_properties.get("contractId", {}).get("const") != \
            "ASSET_CONTEXT_CSV_V1":
        raise AssertionError("Asset Context import result must bind to ASSET_CONTEXT_CSV_V1")
    if asset_context_import_properties.get("semantics", {}).get("const") != \
            "ASSET_SCOPED_ORGANIZATIONAL_CONTEXT_EVIDENCE":
        raise AssertionError("Asset Context import semantics are incorrect")

    asset_context_page = schemas.get("AssetContextEvidencePage", {})
    if asset_context_page.get("properties", {}).get("semantics", {}).get("const") != \
            "CURRENT_PER_SOURCE_ASSET_ORGANIZATIONAL_CONTEXT_EVIDENCE":
        raise AssertionError("Asset Context read semantics must remain current-per-source")
    asset_context_item = schemas.get("AssetContextEvidenceItem", {}).get("properties", {})
    if set(asset_context_item.get("assetIdentityBasis", {}).get("enum", [])) != {
        "SOURCE_NAME_ONLY", "SOURCE_STABLE_ID"
    }:
        raise AssertionError("Asset Context API must preserve canonical asset identity basis")
    if set(asset_context_item.get("environment", {}).get("enum", [])) != {
        "PRODUCTION", "PRE_PRODUCTION", "DEVELOPMENT", "TEST", "SANDBOX",
        "DISASTER_RECOVERY", "UNKNOWN"
    }:
        raise AssertionError("Asset Context environment vocabulary is incomplete")
    if set(asset_context_item.get("businessCriticality", {}).get("enum", [])) != {
        "MISSION_CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"
    }:
        raise AssertionError("Asset Context business criticality vocabulary is incomplete")
    if asset_context_item.get("contextSourceSha256", {}).get("pattern") != "^[a-f0-9]{64}$":
        raise AssertionError("Asset Context API must expose exact source-artifact SHA-256 provenance")
    for timestamp in ("contextObservedAt", "evidenceIngestedAt", "snapshotIngestedAt"):
        if asset_context_item.get(timestamp, {}).get("format") != "date-time":
            raise AssertionError(f"Asset Context API must expose {timestamp} as date-time")
    forbidden_asset_context_fields = {
        "weight", "criticalityWeight", "riskScore", "priority", "priorityTier", "slaDays",
        "threshold", "reachability", "internetExposed", "knownExploited",
        "epssProbability", "cvssBaseScore"
    }
    if forbidden_asset_context_fields.intersection(asset_context_item):
        raise AssertionError(
            "Independent Asset Context evidence must not contain decision or reachability fields"
        )

    reachability_import = schemas.get("NetworkReachabilityImportResult", {})
    required_reachability_import_fields = {
        "insertedSnapshots", "replayedSnapshots", "snapshotConflictGroups",
        "insertedEvidence", "replayedEvidence", "persistenceQuarantinedRows",
        "contractQuarantinedRows", "totalQuarantinedRows", "originScopeDistribution",
        "protocolDistribution", "reachabilityStatusDistribution", "reachabilityMethodDistribution",
    }
    if not required_reachability_import_fields.issubset(set(reachability_import.get("required", []))):
        raise AssertionError("Network Reachability import result schema is incomplete")
    reachability_import_properties = reachability_import.get("properties", {})
    if reachability_import_properties.get("contractId", {}).get("const") != "NETWORK_REACHABILITY_CSV_V1":
        raise AssertionError("Network Reachability import result must bind to NETWORK_REACHABILITY_CSV_V1")
    if reachability_import_properties.get("semantics", {}).get("const") !=             "ASSET_ENDPOINT_ORIGIN_SCOPED_NETWORK_REACHABILITY_EVIDENCE":
        raise AssertionError("Network Reachability import semantics are incorrect")

    reachability_page = schemas.get("NetworkReachabilityEvidencePage", {})
    if reachability_page.get("properties", {}).get("semantics", {}).get("const") !=             "CURRENT_PER_SOURCE_SCOPED_NETWORK_REACHABILITY_EVIDENCE":
        raise AssertionError("Network Reachability read semantics must remain scoped current-per-source")
    reachability_item = schemas.get("NetworkReachabilityEvidenceItem", {}).get("properties", {})
    if set(reachability_item.get("assetIdentityBasis", {}).get("enum", [])) != {"SOURCE_NAME_ONLY", "SOURCE_STABLE_ID"}:
        raise AssertionError("Network Reachability API must preserve canonical asset identity basis")
    if set(reachability_item.get("originScope", {}).get("enum", [])) != {"INTERNET", "EXTERNAL_PARTNER", "INTERNAL_ENTERPRISE", "LOCAL_SEGMENT", "OTHER", "UNKNOWN"}:
        raise AssertionError("Network Reachability origin vocabulary is incomplete")
    if set(reachability_item.get("transportProtocol", {}).get("enum", [])) != {"TCP", "UDP", "ICMP", "OTHER", "UNKNOWN"}:
        raise AssertionError("Network Reachability protocol vocabulary is incomplete")
    if set(reachability_item.get("reachabilityStatus", {}).get("enum", [])) != {"REACHABLE", "NOT_REACHABLE", "UNKNOWN"}:
        raise AssertionError("Network Reachability status vocabulary is incomplete")
    if set(reachability_item.get("reachabilityMethod", {}).get("enum", [])) != {"ACTIVE_PROBE", "CONTROL_PLANE", "FIREWALL_POLICY", "CLOUD_CONFIGURATION", "PASSIVE_OBSERVATION", "OTHER", "UNKNOWN"}:
        raise AssertionError("Network Reachability method vocabulary is incomplete")
    target_port = reachability_item.get("targetPort", {})
    if target_port.get("minimum") != 1 or target_port.get("maximum") != 65535:
        raise AssertionError("Network Reachability targetPort must preserve 1..65535 bounds")
    if target_port.get("type") != ["integer", "null"]:
        raise AssertionError("Network Reachability targetPort must preserve portless evidence as null")
    if reachability_item.get("evidenceSourceSha256", {}).get("pattern") != "^[a-f0-9]{64}$":
        raise AssertionError("Network Reachability API must expose exact source-artifact SHA-256 provenance")
    for timestamp in ("evidenceObservedAt", "evidenceIngestedAt", "snapshotIngestedAt"):
        if reachability_item.get(timestamp, {}).get("format") != "date-time":
            raise AssertionError(f"Network Reachability API must expose {timestamp} as date-time")
    forbidden_reachability_fields = {
        "internetExposed", "internet_exposed", "riskScore", "priority", "priorityTier",
        "slaDays", "businessCriticality", "criticalityWeight", "cvssBaseScore",
        "epssProbability", "knownExploited", "applicabilityStatus", "attackPathScore"
    }
    if forbidden_reachability_fields.intersection(reachability_item):
        raise AssertionError("Independent Network Reachability evidence must not contain decision fields")

    business_impact_import = schemas.get("BusinessImpactImportResult", {})
    required_business_impact_import_fields = {
        "insertedSnapshots", "replayedSnapshots", "snapshotConflictGroups",
        "insertedEvidence", "replayedEvidence", "persistenceQuarantinedRows",
        "contractQuarantinedRows", "totalQuarantinedRows", "impactDimensionDistribution",
        "impactLevelDistribution", "impactMethodDistribution",
    }
    if not required_business_impact_import_fields.issubset(set(business_impact_import.get("required", []))):
        raise AssertionError("Business Impact import result schema is incomplete")
    business_impact_import_properties = business_impact_import.get("properties", {})
    if business_impact_import_properties.get("contractId", {}).get("const") != "BUSINESS_IMPACT_CSV_V1":
        raise AssertionError("Business Impact import result must bind to BUSINESS_IMPACT_CSV_V1")
    if business_impact_import_properties.get("semantics", {}).get("const") !=             "ASSET_SERVICE_SCOPED_BUSINESS_MISSION_IMPACT_EVIDENCE":
        raise AssertionError("Business Impact import semantics are incorrect")

    business_impact_page = schemas.get("BusinessImpactEvidencePage", {})
    if business_impact_page.get("properties", {}).get("semantics", {}).get("const") !=             "CURRENT_PER_SOURCE_ASSET_SERVICE_BUSINESS_MISSION_IMPACT_EVIDENCE":
        raise AssertionError("Business Impact read semantics must remain current-per-source/service/dimension")
    business_impact_item = schemas.get("BusinessImpactEvidenceItem", {}).get("properties", {})
    if set(business_impact_item.get("assetIdentityBasis", {}).get("enum", [])) != {"SOURCE_NAME_ONLY", "SOURCE_STABLE_ID"}:
        raise AssertionError("Business Impact API must preserve canonical asset identity basis")
    if set(business_impact_item.get("impactDimension", {}).get("enum", [])) != {
        "AVAILABILITY", "INTEGRITY", "CONFIDENTIALITY", "SAFETY", "FINANCIAL",
        "REGULATORY", "OPERATIONAL", "REPUTATIONAL", "MISSION", "OTHER", "UNKNOWN"
    }:
        raise AssertionError("Business Impact dimension vocabulary is incomplete")
    if set(business_impact_item.get("impactLevel", {}).get("enum", [])) != {
        "SEVERE", "HIGH", "MODERATE", "LOW", "NEGLIGIBLE", "UNKNOWN"
    }:
        raise AssertionError("Business Impact qualitative level vocabulary is incomplete")
    if set(business_impact_item.get("impactMethod", {}).get("enum", [])) != {
        "BUSINESS_IMPACT_ANALYSIS", "SERVICE_OWNER_ATTESTATION", "POLICY_CLASSIFICATION",
        "INCIDENT_ANALYSIS", "OTHER", "UNKNOWN"
    }:
        raise AssertionError("Business Impact evidence-method vocabulary is incomplete")
    if business_impact_item.get("impactSourceSha256", {}).get("pattern") != "^[a-f0-9]{64}$":
        raise AssertionError("Business Impact API must expose exact source-artifact SHA-256 provenance")
    for timestamp in ("impactObservedAt", "evidenceIngestedAt", "snapshotIngestedAt"):
        if business_impact_item.get(timestamp, {}).get("format") != "date-time":
            raise AssertionError(f"Business Impact API must expose {timestamp} as date-time")
    forbidden_business_impact_fields = {
        "impactWeight", "numericImpact", "aggregateImpactScore", "monetaryLoss", "lossAmount",
        "riskScore", "priority", "priorityTier", "slaDays", "businessCriticalityWeight",
        "internetExposed", "attackPathScore", "cvssBaseScore", "epssProbability",
        "knownExploited", "applicabilityStatus"
    }
    if forbidden_business_impact_fields.intersection(business_impact_item):
        raise AssertionError("Independent Business Impact evidence must not contain decision fields")

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
