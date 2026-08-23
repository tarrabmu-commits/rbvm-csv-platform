#!/usr/bin/env python3
from pathlib import Path

path = Path("src/main/java/io/rbvm/csv/CsvPlatformServer.java")
text = path.read_text()
original = text

def replace_once(old: str, new: str, label: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one marker, found {count}")
    text = text.replace(old, new, 1)

replace_once(
    "import io.rbvm.postgres.FormulaResultRuntimeFactory;\n",
    "import io.rbvm.postgres.FormulaResultRuntimeFactory;\n"
    "import io.rbvm.postgres.RiskMethodSelectionPolicyRuntimeFactory;\n",
    "runtime factory import",
)

replace_once(
    "    private Optional<DerivedRiskResultHttpRouter> derivedRiskResultRouter = Optional.empty();\n",
    "    private Optional<DerivedRiskResultHttpRouter> derivedRiskResultRouter = Optional.empty();\n"
    "    private Optional<RiskMethodSelectionPolicyHttpRouter> riskMethodSelectionPolicyRouter = Optional.empty();\n",
    "router field",
)

enable_marker = '''    /** Enable the replay-verified V24 derived risk result API before the server is started. */
    public void enableDerivedRiskResultApi(DerivedRiskResultApi api) {
        if (derivedRiskResultRouter.isPresent()) {
            throw new IllegalStateException("Derived Risk Result API is already enabled");
        }
        derivedRiskResultRouter = Optional.of(new DerivedRiskResultHttpRouter(
                Objects.requireNonNull(api, "api")
        ));
    }
'''
replace_once(
    enable_marker,
    enable_marker + '''
    /** Enable exact immutable V25 risk-method selection policy transport before server start. */
    public void enableRiskMethodSelectionPolicyApi(RiskMethodSelectionPolicyApi api) {
        if (riskMethodSelectionPolicyRouter.isPresent()) {
            throw new IllegalStateException("Risk Method Selection Policy API is already enabled");
        }
        riskMethodSelectionPolicyRouter = Optional.of(new RiskMethodSelectionPolicyHttpRouter(
                Objects.requireNonNull(api, "api")
        ));
    }
''',
    "enable method",
)

route_marker = '            if ("/api/v1/cases".equals(path)) {'
risk_route = '''            if (RiskMethodSelectionPolicyHttpRouter.inNamespace(path)) {
                if (!RiskMethodSelectionPolicyHttpRouter.handles(path)) {
                    throw new HttpProblem(
                            404,
                            "NOT_FOUND",
                            "The requested risk method selection policy route does not exist"
                    );
                }
                ApiRole requiredRole = RiskMethodSelectionPolicyHttpRouter.requiredRole(exchange, method);
                AuthPrincipal principal = authorize(exchange, requiredRole);
                RiskMethodSelectionPolicyHttpRouter riskMethodPolicies =
                        riskMethodSelectionPolicyRouter.orElseThrow(() -> new HttpProblem(
                                503,
                                "RISK_METHOD_SELECTION_POLICY_PERSISTENCE_UNAVAILABLE",
                                "Risk Method Selection Policy API requires PostgreSQL schema version 25 or newer"
                        ));
                riskMethodPolicies.routeAuthorized(exchange, method, principal);
                return;
            }
'''
replace_once(route_marker, risk_route + route_marker, "authorized route")

catch_marker = '''        } catch (DerivedRiskResultApi.ApiProblem problem) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, problem.status(), problem.code(), problem.getMessage(), correlationId);
'''
replace_once(
    catch_marker,
    '''        } catch (RiskMethodSelectionPolicyApi.ApiProblem problem) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, problem.status(), problem.code(), problem.getMessage(), correlationId);
''' + catch_marker,
    "API problem mapping",
)

health_marker = '''        health.put("derivedRiskResults", Map.of(
                "catalogEnabled", derivedRiskResultRouter.isPresent(),
                "readEnabled", derivedRiskResultRouter.isPresent(),
                "materializationEnabled", derivedRiskResultRouter.isPresent(),
                "replayVerified", derivedRiskResultRouter.isPresent()
        ));
        return health;
'''
replace_once(
    health_marker,
    '''        health.put("derivedRiskResults", Map.of(
                "catalogEnabled", derivedRiskResultRouter.isPresent(),
                "readEnabled", derivedRiskResultRouter.isPresent(),
                "materializationEnabled", derivedRiskResultRouter.isPresent(),
                "replayVerified", derivedRiskResultRouter.isPresent()
        ));
        health.put("riskMethodSelectionPolicies", Map.of(
                "exactReadEnabled", riskMethodSelectionPolicyRouter.isPresent(),
                "installationEnabled", riskMethodSelectionPolicyRouter.isPresent(),
                "selectionSemantics", "EXACT_REVISION_AND_SHA_NO_CURRENT_LATEST_OR_DEFAULT"
        ));
        return health;
''',
    "health capability",
)

metrics_marker = '''                + "# TYPE rbvm_process_uptime_seconds gauge\\n"
'''
replace_once(
    metrics_marker,
    '''                + "# TYPE rbvm_risk_method_selection_policy_api_enabled gauge\\n"
                + "rbvm_risk_method_selection_policy_api_enabled "
                + (riskMethodSelectionPolicyRouter.isPresent() ? 1 : 0) + "\\n"
''' + metrics_marker,
    "metrics capability",
)

runtime_marker = '''        Optional<DerivedRiskResultRuntimeFactory.Runtime> derivedRiskResultRuntime =
                DerivedRiskResultRuntimeFactory.fromEnvironment(System.getenv());
'''
replace_once(
    runtime_marker,
    runtime_marker + '''        Optional<RiskMethodSelectionPolicyRuntimeFactory.Runtime> riskMethodSelectionPolicyRuntime =
                RiskMethodSelectionPolicyRuntimeFactory.fromEnvironment(System.getenv());
''',
    "runtime discovery",
)

enable_runtime_marker = '''        application.start();
'''
replace_once(
    enable_runtime_marker,
    '''        riskMethodSelectionPolicyRuntime.ifPresent(context ->
                application.enableRiskMethodSelectionPolicyApi(
                        new RiskMethodSelectionPolicyApi(context.policies())
                )
        );
''' + enable_runtime_marker,
    "runtime enable",
)

log_marker = '''        System.out.println("API authentication: "
'''
replace_once(
    log_marker,
    '''        System.out.println("Risk Method Selection Policy API: "
                + (riskMethodSelectionPolicyRuntime.isPresent() ? "ENABLED" : "DISABLED"));
''' + log_marker,
    "startup log",
)

if text == original:
    raise SystemExit("server patch produced no change")
path.write_text(text)
print("CsvPlatformServer risk method selection API wiring: PATCHED")
