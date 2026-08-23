#!/usr/bin/env python3
from pathlib import Path

path = Path('src/main/java/io/rbvm/csv/CsvPlatformServer.java')
text = path.read_text(encoding='utf-8')


def replace_once(old: str, new: str) -> None:
    global text
    if new in text:
        return
    if text.count(old) != 1:
        raise SystemExit(f'expected exactly one server marker, found {text.count(old)}: {old[:80]!r}')
    text = text.replace(old, new, 1)

replace_once(
    'import io.rbvm.postgres.ApplicabilityFindingExporter;\n',
    'import io.rbvm.postgres.ActiveRiskMethodExecutionRuntimeFactory;\n'
    'import io.rbvm.postgres.ApplicabilityFindingExporter;\n'
)

replace_once(
    '    private Optional<RiskMethodSelectionPolicyHttpRouter> riskMethodSelectionPolicyRouter = Optional.empty();\n',
    '    private Optional<RiskMethodSelectionPolicyHttpRouter> riskMethodSelectionPolicyRouter = Optional.empty();\n'
    '    private Optional<ActiveRiskMethodExecutionHttpRouter> activeRiskMethodExecutionRouter = Optional.empty();\n'
)

policy_enable = '''    /** Enable exact immutable V25 risk-method selection policy transport before server start. */
    public void enableRiskMethodSelectionPolicyApi(RiskMethodSelectionPolicyApi api) {
        if (riskMethodSelectionPolicyRouter.isPresent()) {
            throw new IllegalStateException("Risk Method Selection Policy API is already enabled");
        }
        riskMethodSelectionPolicyRouter = Optional.of(new RiskMethodSelectionPolicyHttpRouter(
                Objects.requireNonNull(api, "api")
        ));
    }
'''
replace_once(
    policy_enable,
    policy_enable + '''
    /** Enable exact immutable V27 active-risk-method execution transport before server start. */
    public void enableActiveRiskMethodExecutionApi(ActiveRiskMethodExecutionApi api) {
        if (activeRiskMethodExecutionRouter.isPresent()) {
            throw new IllegalStateException("Active Risk Method Execution API is already enabled");
        }
        activeRiskMethodExecutionRouter = Optional.of(new ActiveRiskMethodExecutionHttpRouter(
                Objects.requireNonNull(api, "api")
        ));
    }
'''
)

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
active_route = '''            if (ActiveRiskMethodExecutionHttpRouter.inNamespace(path)) {
                if (!ActiveRiskMethodExecutionHttpRouter.handles(path)) {
                    throw new HttpProblem(
                            404,
                            "NOT_FOUND",
                            "The requested active risk method execution route does not exist"
                    );
                }
                ApiRole requiredRole = ActiveRiskMethodExecutionHttpRouter.requiredRole(exchange, method);
                AuthPrincipal principal = authorize(exchange, requiredRole);
                ActiveRiskMethodExecutionHttpRouter executions =
                        activeRiskMethodExecutionRouter.orElseThrow(() -> new HttpProblem(
                                503,
                                "ACTIVE_RISK_METHOD_EXECUTION_PERSISTENCE_UNAVAILABLE",
                                "Active Risk Method Execution API requires PostgreSQL schema version 27 or newer"
                        ));
                executions.routeAuthorized(exchange, method, principal);
                return;
            }
'''
replace_once(risk_route, active_route + risk_route)

replace_once(
    '        } catch (RiskMethodSelectionPolicyApi.ApiProblem problem) {\n',
    '        } catch (ActiveRiskMethodExecutionApi.ApiProblem problem) {\n'
    '            problemsTotal.incrementAndGet();\n'
    '            sendProblem(exchange, problem.status(), problem.code(), problem.getMessage(), correlationId);\n'
    '        } catch (RiskMethodSelectionPolicyApi.ApiProblem problem) {\n'
)

health_policy = '''        health.put("riskMethodSelectionPolicies", Map.of(
                "exactReadEnabled", riskMethodSelectionPolicyRouter.isPresent(),
                "installationEnabled", riskMethodSelectionPolicyRouter.isPresent(),
                "selectionSemantics", "EXACT_REVISION_AND_SHA_NO_CURRENT_LATEST_OR_DEFAULT"
        ));
'''
replace_once(
    health_policy,
    health_policy + '''        health.put("activeRiskMethodExecutions", Map.of(
                "exactExecutionEnabled", activeRiskMethodExecutionRouter.isPresent(),
                "exactBindingReadEnabled", activeRiskMethodExecutionRouter.isPresent(),
                "executionSemantics", ActiveRiskMethodExecutionApi.EXECUTION_SEMANTICS
        ));
'''
)

metric_policy = '''                + "# TYPE rbvm_risk_method_selection_policy_api_enabled gauge\\n"
                + "rbvm_risk_method_selection_policy_api_enabled "
                + (riskMethodSelectionPolicyRouter.isPresent() ? 1 : 0) + "\\n"
'''
replace_once(
    metric_policy,
    metric_policy + '''                + "# TYPE rbvm_active_risk_method_execution_api_enabled gauge\\n"
                + "rbvm_active_risk_method_execution_api_enabled "
                + (activeRiskMethodExecutionRouter.isPresent() ? 1 : 0) + "\\n"
'''
)

runtime_policy = '''        Optional<RiskMethodSelectionPolicyRuntimeFactory.Runtime> riskMethodSelectionPolicyRuntime =
                RiskMethodSelectionPolicyRuntimeFactory.fromEnvironment(System.getenv());
'''
replace_once(
    runtime_policy,
    runtime_policy + '''        Optional<ActiveRiskMethodExecutionRuntimeFactory.Runtime> activeRiskMethodExecutionRuntime =
                ActiveRiskMethodExecutionRuntimeFactory.fromEnvironment(System.getenv());
'''
)

policy_wiring = '''        riskMethodSelectionPolicyRuntime.ifPresent(context ->
                application.enableRiskMethodSelectionPolicyApi(
                        new RiskMethodSelectionPolicyApi(context.policies())
                )
        );
'''
replace_once(
    policy_wiring,
    policy_wiring + '''        activeRiskMethodExecutionRuntime.ifPresent(context ->
                application.enableActiveRiskMethodExecutionApi(
                        new ActiveRiskMethodExecutionApi(context.bindings(), context.materializer())
                )
        );
'''
)

policy_print = '''        System.out.println("Risk Method Selection Policy API: "
                + (riskMethodSelectionPolicyRuntime.isPresent() ? "ENABLED" : "DISABLED"));
'''
replace_once(
    policy_print,
    policy_print + '''        System.out.println("Active Risk Method Execution API: "
                + (activeRiskMethodExecutionRuntime.isPresent() ? "ENABLED" : "DISABLED"));
'''
)

path.write_text(text, encoding='utf-8')
print('CsvPlatformServer active risk method execution wiring: PATCHED')
