#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

api_path = ROOT / "src/main/java/io/rbvm/csv/RiskMethodSelectionPolicyApi.java"
api = api_path.read_text(encoding="utf-8")
start_marker = "    private Response resolvedSelectionResponse(\n"
end_marker = "    private static Response response(\n"
start = api.find(start_marker)
end = api.find(end_marker, start + 1)
if start < 0 or end < 0 or end <= start:
    raise SystemExit("resolved-selection helper boundaries are not unique")
helper = '''    private Response resolvedSelectionResponse(
            RbvmRiskMethodSelectionPolicyActivationEvent event
    ) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("contractId", RESOLVED_ACTIVE_METHOD_CONTRACT_ID);
        body.put("resolutionSemantics", RESOLVED_ACTIVE_METHOD_SEMANTICS);
        body.put("selectionState", event.activatesPolicy() ? "ACTIVE" : "CLEARED");
        body.put("activation", activationView(event));

        if (event.activatesPolicy()) {
            RbvmRiskMethodSelectionPolicy policy = policies.findByRevision(event.policyRevision())
                    .filter(candidate -> candidate.policySha256().equals(event.policySha256()))
                    .orElseThrow(() -> new ApiProblem(
                            500,
                            "RISK_METHOD_SELECTION_POLICY_ACTIVATION_INTEGRITY_FAILURE",
                            "ACTIVE activation references an exact policy identity that cannot be resolved"
                    ));
            body.put("policy", policyView(policy));
            body.put("selectedMethod", selectedMethodView(policy));
        } else {
            body.put("policy", null);
            body.put("selectedMethod", null);
        }

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("ETag", activationStrongEtag(event.eventSha256()));
        headers.put("Location", resolvedActivationLocation(event));
        return new Response(200, headers, body);
    }

    private static Map<String, Object> selectedMethodView(
            RbvmRiskMethodSelectionPolicy policy
    ) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("selectionRole", policy.selectionRole().name());
        output.put("methodFamily", policy.methodFamily().name());
        output.put("methodId", policy.methodId());
        output.put("methodVersion", policy.methodVersion());
        output.put("methodSha256", policy.methodSha256());
        return output;
    }

'''
api_path.write_text(api[:start] + helper + api[end:], encoding="utf-8")

combined_path = ROOT / "api/openapi.yaml"
combined = combined_path.read_text(encoding="utf-8")
combined_marker = "  /risk-method-selection-policy-activation/current:\n"
combined_block = """  /risk-method-selection-policy-activation/current/resolved:\n    $ref: './resolved-active-risk-method-v1.openapi.yaml#/paths/~1api~1v1~1risk-method-selection-policy-activation~1current~1resolved'\n  /risk-method-selection-policy-activations/{activationRevision}/{eventSha256}/resolved:\n    $ref: './resolved-active-risk-method-v1.openapi.yaml#/paths/~1api~1v1~1risk-method-selection-policy-activations~1{activationRevision}~1{eventSha256}~1resolved'\n"""
resolved_needles = (
    "/risk-method-selection-policy-activation/current/resolved:",
    "/risk-method-selection-policy-activations/{activationRevision}/{eventSha256}/resolved:",
)
if all(needle in combined for needle in resolved_needles):
    pass
elif any(needle in combined for needle in resolved_needles):
    raise SystemExit("combined OpenAPI contains a partial resolved-method patch")
else:
    if combined.count(combined_marker) != 1:
        raise SystemExit("combined OpenAPI insertion marker is not unique")
    combined = combined.replace(combined_marker, combined_block + combined_marker, 1)
    combined_path.write_text(combined, encoding="utf-8")

composed_path = ROOT / "api/openapi-v21.yaml"
composed = composed_path.read_text(encoding="utf-8")
composed_marker = "  /risk-method-selection-policy-activation/current: {$ref: './risk-method-selection-policy-activation-v1.openapi.yaml#/paths/~1api~1v1~1risk-method-selection-policy-activation~1current'}\n"
composed_block = """  /risk-method-selection-policy-activation/current/resolved: {$ref: './resolved-active-risk-method-v1.openapi.yaml#/paths/~1api~1v1~1risk-method-selection-policy-activation~1current~1resolved'}\n  /risk-method-selection-policy-activations/{activationRevision}/{eventSha256}/resolved: {$ref: './resolved-active-risk-method-v1.openapi.yaml#/paths/~1api~1v1~1risk-method-selection-policy-activations~1{activationRevision}~1{eventSha256}~1resolved'}\n"""
if all(needle in composed for needle in resolved_needles):
    pass
elif any(needle in composed for needle in resolved_needles):
    raise SystemExit("composed OpenAPI contains a partial resolved-method patch")
else:
    if composed.count(composed_marker) != 1:
        raise SystemExit("composed OpenAPI insertion marker is not unique")
    composed = composed.replace(composed_marker, composed_block + composed_marker, 1)
    composed_path.write_text(composed, encoding="utf-8")

print("Resolved active risk method API finalization: PASS")
