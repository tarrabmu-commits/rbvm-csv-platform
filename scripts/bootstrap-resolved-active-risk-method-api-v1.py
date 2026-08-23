#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

api_path = ROOT / "src/main/java/io/rbvm/csv/RiskMethodSelectionPolicyApi.java"
api = api_path.read_text(encoding="utf-8")

constants_marker = '''    public static final String ACTIVATION_SELECTION_SEMANTICS =
            "CURRENT_IS_GREATEST_EXPLICIT_ACTIVATION_REVISION_NEVER_POLICY_REVISION";
'''
constants_block = constants_marker + '''    public static final String RESOLVED_ACTIVE_METHOD_CONTRACT_ID =
            "RBVM_RESOLVED_ACTIVE_RISK_METHOD_API_V1";
    public static final String RESOLVED_ACTIVE_METHOD_SEMANTICS =
            "EXPLICIT_ACTIVATION_TO_EXACT_POLICY_TO_EXACT_METHOD_NO_DEFAULT";
'''
if "RESOLVED_ACTIVE_METHOD_CONTRACT_ID" not in api:
    if api.count(constants_marker) != 1:
        raise SystemExit("API constants insertion marker is not unique")
    api = api.replace(constants_marker, constants_block, 1)

current_insert_marker = '''    /** Exact activation lookup requires both activation revision and canonical event SHA. */
'''
current_method = '''    /**
     * Resolves the greatest explicit activation event through its exact persisted policy identity.
     * The returned activation revision and event SHA are the replay anchor; "current" itself is not.
     */
    public Response resolvedCurrentSelection() throws IOException {
        RbvmRiskMethodSelectionPolicyActivationEvent event = activationStore().current()
                .orElseThrow(() -> new ApiProblem(
                        404,
                        "RISK_METHOD_SELECTION_POLICY_ACTIVATION_NOT_FOUND",
                        "No explicit risk method selection policy activation event has been persisted"
                ));
        return resolvedSelectionResponse(event);
    }

'''
if "resolvedCurrentSelection()" not in api:
    if api.count(current_insert_marker) != 1:
        raise SystemExit("resolved-current insertion marker is not unique")
    api = api.replace(current_insert_marker, current_method + current_insert_marker, 1)

exact_insert_marker = '''    /**
     * Appends or exactly replays one ACTIVE event. The authenticated actor and explicit recordedAt
'''
exact_method = '''    /** Resolves one exact historical activation identity through its exact persisted policy. */
    public Response resolvedActivation(int activationRevision, String eventSha256) throws IOException {
        int exactRevision = requireActivationRevision(activationRevision);
        String exactSha = requireSha(eventSha256, "eventSha256");
        RbvmRiskMethodSelectionPolicyActivationEvent event = activationStore()
                .findByActivationRevision(exactRevision)
                .filter(candidate -> candidate.eventSha256().equals(exactSha))
                .orElseThrow(() -> new ApiProblem(
                        404,
                        "RISK_METHOD_SELECTION_POLICY_ACTIVATION_NOT_FOUND",
                        "No persisted activation event matches the exact activation revision and event SHA"
                ));
        return resolvedSelectionResponse(event);
    }

'''
if "resolvedActivation(int activationRevision" not in api:
    if api.count(exact_insert_marker) != 1:
        raise SystemExit("resolved-exact insertion marker is not unique")
    api = api.replace(exact_insert_marker, exact_method + exact_insert_marker, 1)

response_insert_marker = '''    private static Response response(
            int status,
            RbvmRiskMethodSelectionPolicy policy,
'''
resolution_helpers = '''    private Response resolvedSelectionResponse(
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

    private static Map<String, Object> selectedMethodView(RbvmRiskMethodSelectionPolicy policy) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("selectionRole", policy.selectionRole().name());
        output.put("methodFamily", policy.methodFamily().name());
        output.put("methodId", policy.methodId());
        output.put("methodVersion", policy.methodVersion());
        output.put("methodSha256", policy.methodSha256());
        return output;
    }

'''
if "resolvedSelectionResponse(" not in api:
    if api.count(response_insert_marker) != 1:
        raise SystemExit("resolution helper insertion marker is not unique")
    api = api.replace(response_insert_marker, resolution_helpers + response_insert_marker, 1)

location_marker = '''    static String activationLocation(RbvmRiskMethodSelectionPolicyActivationEvent event) {
        return "/api/v1/risk-method-selection-policy-activations/"
                + event.activationRevision() + "/" + event.eventSha256();
    }
'''
location_block = location_marker + '''
    static String resolvedActivationLocation(RbvmRiskMethodSelectionPolicyActivationEvent event) {
        return activationLocation(event) + "/resolved";
    }
'''
if "resolvedActivationLocation(" not in api:
    if api.count(location_marker) != 1:
        raise SystemExit("resolved location insertion marker is not unique")
    api = api.replace(location_marker, location_block, 1)

api_path.write_text(api, encoding="utf-8")

router_path = ROOT / "src/main/java/io/rbvm/csv/RiskMethodSelectionPolicyHttpRouter.java"
router = router_path.read_text(encoding="utf-8")

current_constant = '''    private static final String ACTIVATION_CURRENT =
            "/api/v1/risk-method-selection-policy-activation/current";
'''
current_constant_block = current_constant + '''    private static final String ACTIVATION_CURRENT_RESOLVED =
            "/api/v1/risk-method-selection-policy-activation/current/resolved";
'''
if "ACTIVATION_CURRENT_RESOLVED" not in router:
    if router.count(current_constant) != 1:
        raise SystemExit("router current constant marker is not unique")
    router = router.replace(current_constant, current_constant_block, 1)

activation_pattern = '''    private static final Pattern ACTIVATION_ITEM = Pattern.compile(
            "^/api/v1/risk-method-selection-policy-activations/([1-9][0-9]*)/([a-f0-9]{64})$"
    );
'''
activation_pattern_block = activation_pattern + '''    private static final Pattern ACTIVATION_RESOLVED_ITEM = Pattern.compile(
            "^/api/v1/risk-method-selection-policy-activations/([1-9][0-9]*)/([a-f0-9]{64})/resolved$"
    );
'''
if "ACTIVATION_RESOLVED_ITEM" not in router:
    if router.count(activation_pattern) != 1:
        raise SystemExit("router activation pattern marker is not unique")
    router = router.replace(activation_pattern, activation_pattern_block, 1)

namespace_marker = '''                || ACTIVATION_CURRENT.equals(path)
                || ACTIVATION_NAMESPACE.equals(path)
'''
namespace_block = '''                || ACTIVATION_CURRENT.equals(path)
                || ACTIVATION_CURRENT_RESOLVED.equals(path)
                || ACTIVATION_NAMESPACE.equals(path)
'''
if "|| ACTIVATION_CURRENT_RESOLVED.equals(path)" not in router:
    if router.count(namespace_marker) != 1:
        raise SystemExit("router namespace marker is not unique")
    router = router.replace(namespace_marker, namespace_block, 1)

handles_marker = '''                || ACTIVATION_CURRENT.equals(path)
                || ACTIVATION_ITEM.matcher(path).matches()
'''
handles_block = '''                || ACTIVATION_CURRENT.equals(path)
                || ACTIVATION_CURRENT_RESOLVED.equals(path)
                || ACTIVATION_ITEM.matcher(path).matches()
                || ACTIVATION_RESOLVED_ITEM.matcher(path).matches()
'''
if "|| ACTIVATION_RESOLVED_ITEM.matcher(path).matches()" not in router:
    if router.count(handles_marker) != 1:
        raise SystemExit("router handles marker is not unique")
    router = router.replace(handles_marker, handles_block, 1)

role_marker = '''        if (POLICY_ITEM.matcher(path).matches()
                || ACTIVATION_CURRENT.equals(path)
                || ACTIVATION_ITEM.matcher(path).matches()) {
'''
role_block = '''        if (POLICY_ITEM.matcher(path).matches()
                || ACTIVATION_CURRENT.equals(path)
                || ACTIVATION_CURRENT_RESOLVED.equals(path)
                || ACTIVATION_ITEM.matcher(path).matches()
                || ACTIVATION_RESOLVED_ITEM.matcher(path).matches()) {
'''
if "|| ACTIVATION_CURRENT_RESOLVED.equals(path)" not in router[router.index("static ApiRole requiredRole"):]:
    if router.count(role_marker) != 1:
        raise SystemExit("router role marker is not unique")
    router = router.replace(role_marker, role_block, 1)

route_marker = '''        if (ACTIVATION_CURRENT.equals(path)) {
            if (!"GET".equals(method)) requiredRole(exchange, method);
            rejectBody(exchange, "Current explicit activation read does not accept a request body");
            send(exchange, api.currentActivation());
            return;
        }

        Matcher activation = ACTIVATION_ITEM.matcher(path);
'''
route_block = '''        if (ACTIVATION_CURRENT_RESOLVED.equals(path)) {
            if (!"GET".equals(method)) requiredRole(exchange, method);
            rejectBody(exchange, "Resolved current activation read does not accept a request body");
            send(exchange, api.resolvedCurrentSelection());
            return;
        }

        if (ACTIVATION_CURRENT.equals(path)) {
            if (!"GET".equals(method)) requiredRole(exchange, method);
            rejectBody(exchange, "Current explicit activation read does not accept a request body");
            send(exchange, api.currentActivation());
            return;
        }

        Matcher resolvedActivation = ACTIVATION_RESOLVED_ITEM.matcher(path);
        if (resolvedActivation.matches()) {
            if (!"GET".equals(method)) requiredRole(exchange, method);
            rejectBody(exchange, "Resolved exact activation read does not accept a request body");
            send(exchange, api.resolvedActivation(
                    positiveInteger(resolvedActivation.group(1), "activationRevision"),
                    resolvedActivation.group(2)
            ));
            return;
        }

        Matcher activation = ACTIVATION_ITEM.matcher(path);
'''
if "api.resolvedCurrentSelection()" not in router:
    if router.count(route_marker) != 1:
        raise SystemExit("router resolved-route marker is not unique")
    router = router.replace(route_marker, route_block, 1)

router_path.write_text(router, encoding="utf-8")
print("Resolved active risk method API bootstrap: PASS")
