package io.rbvm.csv;

import io.rbvm.decision.RbvmDerivedRiskMethodology;
import io.rbvm.decision.RbvmDerivedRiskMethodologyCatalog;
import io.rbvm.decision.RbvmFormulaV1;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy;
import io.rbvm.postgres.RiskMethodSelectionPolicyInstallResult;
import io.rbvm.postgres.RiskMethodSelectionPolicyStore;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

public final class RiskMethodSelectionPolicyApiSelfTest {
    private RiskMethodSelectionPolicyApiSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        installsAndReadsExactFormulaPolicy();
        installsDerivedMethodsOnlyByExactCanonicalIdentity();
        rejectsRevisionConflictWithoutOverwrite();
        rejectsMissingOrMalformedExactIdentity();
        System.out.println("RiskMethodSelectionPolicyApiSelfTest: PASS");
    }

    private static void installsAndReadsExactFormulaPolicy() throws Exception {
        InMemoryStore store = new InMemoryStore();
        RiskMethodSelectionPolicyApi api = new RiskMethodSelectionPolicyApi(store);
        RiskMethodSelectionPolicyApi.Response inserted = api.install(
                1,
                "RBVM_FORMULA",
                RbvmFormulaV1.FORMULA_ID,
                RbvmFormulaV1.FORMULA_VERSION,
                RbvmFormulaV1.FORMULA_SHA256
        );
        assert inserted.status() == 201;
        Map<?, ?> policy = (Map<?, ?>) inserted.body().get("policy");
        String policySha = policy.get("policySha256").toString();
        assert inserted.body().get("installationStatus").equals("INSERTED");
        assert inserted.body().get("selectionSemantics")
                .equals("EXACT_REVISION_AND_SHA_NO_CURRENT_LATEST_OR_DEFAULT");
        assert inserted.headers().get("Location").equals(
                "/api/v1/risk-method-selection-policies/1/" + policySha
        );
        assert inserted.headers().get("ETag").equals(
                "\"risk-method-selection-policy-" + policySha + "\""
        );

        RiskMethodSelectionPolicyApi.Response replay = api.install(
                1,
                "RBVM_FORMULA",
                RbvmFormulaV1.FORMULA_ID,
                RbvmFormulaV1.FORMULA_VERSION,
                RbvmFormulaV1.FORMULA_SHA256
        );
        assert replay.status() == 200;
        assert replay.body().get("installationStatus").equals("REPLAYED");

        RiskMethodSelectionPolicyApi.Response read = api.get(1, policySha);
        assert read.status() == 200;
        assert read.body().get("contractId").equals(RiskMethodSelectionPolicyApi.CONTRACT_ID);
        Map<?, ?> readPolicy = (Map<?, ?>) read.body().get("policy");
        assert readPolicy.get("methodFamily").equals("RBVM_FORMULA");
        assert readPolicy.get("methodId").equals(RbvmFormulaV1.FORMULA_ID);
        assert readPolicy.get("methodVersion").equals(1);
        assert readPolicy.get("methodSha256").equals(RbvmFormulaV1.FORMULA_SHA256);
        assert readPolicy.get("canonicalPayloadBase64") != null;
    }

    private static void installsDerivedMethodsOnlyByExactCanonicalIdentity() throws Exception {
        InMemoryStore store = new InMemoryStore();
        RiskMethodSelectionPolicyApi api = new RiskMethodSelectionPolicyApi(store);
        int revision = 1;
        for (RbvmDerivedRiskMethodology.Definition definition
                : RbvmDerivedRiskMethodologyCatalog.definitions()) {
            RiskMethodSelectionPolicyApi.Response response = api.install(
                    revision++,
                    "STANDARD_DERIVED",
                    definition.methodologyId(),
                    definition.version(),
                    definition.methodologySha256()
            );
            assert response.status() == 201;
        }
        assert store.size() == 2;

        RbvmDerivedRiskMethodology.Definition definition =
                RbvmDerivedRiskMethodologyCatalog.definitions().get(0);
        expectProblem(
                404,
                "RISK_METHOD_NOT_FOUND",
                () -> api.install(
                        3,
                        "STANDARD_DERIVED",
                        definition.methodologyId().toLowerCase(),
                        definition.version(),
                        definition.methodologySha256()
                )
        );
        expectProblem(
                404,
                "RISK_METHOD_NOT_FOUND",
                () -> api.install(
                        3,
                        "STANDARD_DERIVED",
                        definition.methodologyId(),
                        definition.version(),
                        "0".repeat(64)
                )
        );
    }

    private static void rejectsRevisionConflictWithoutOverwrite() throws Exception {
        InMemoryStore store = new InMemoryStore();
        RiskMethodSelectionPolicyApi api = new RiskMethodSelectionPolicyApi(store);
        api.install(
                1,
                "RBVM_FORMULA",
                RbvmFormulaV1.FORMULA_ID,
                RbvmFormulaV1.FORMULA_VERSION,
                RbvmFormulaV1.FORMULA_SHA256
        );
        RbvmDerivedRiskMethodology.Definition definition =
                RbvmDerivedRiskMethodologyCatalog.definitions().get(0);
        expectProblem(
                409,
                "RISK_METHOD_SELECTION_POLICY_REVISION_CONFLICT",
                () -> api.install(
                        1,
                        "STANDARD_DERIVED",
                        definition.methodologyId(),
                        definition.version(),
                        definition.methodologySha256()
                )
        );
        assert store.size() == 1;
        assert store.findByRevision(1).orElseThrow().methodFamily()
                == RbvmRiskMethodSelectionPolicy.MethodFamily.RBVM_FORMULA;
    }

    private static void rejectsMissingOrMalformedExactIdentity() throws Exception {
        InMemoryStore store = new InMemoryStore();
        RiskMethodSelectionPolicyApi api = new RiskMethodSelectionPolicyApi(store);
        RbvmRiskMethodSelectionPolicy formula = RbvmRiskMethodSelectionPolicy.formulaV1(1);
        store.install(formula);
        expectProblem(404, "RISK_METHOD_SELECTION_POLICY_NOT_FOUND",
                () -> api.get(1, "0".repeat(64)));
        expectProblem(400, "INVALID_RISK_METHOD_SELECTION_POLICY_IDENTITY",
                () -> api.get(0, formula.policySha256()));
        expectProblem(400, "INVALID_RISK_METHOD_SELECTION_POLICY_IDENTITY",
                () -> api.install(2, "UNKNOWN", "x", 1, "0".repeat(64)));
        expectProblem(400, "INVALID_RISK_METHOD_SELECTION_POLICY_IDENTITY",
                () -> api.install(2, "RBVM_FORMULA", " RBVM_FORMULA_V1", 1,
                        RbvmFormulaV1.FORMULA_SHA256));
    }

    private static void expectProblem(int status, String code, ThrowingAction action)
            throws Exception {
        boolean rejected = false;
        try {
            action.run();
        } catch (RiskMethodSelectionPolicyApi.ApiProblem problem) {
            rejected = problem.status() == status && problem.code().equals(code);
        }
        assert rejected : "expected API problem " + status + " " + code;
    }

    @FunctionalInterface
    private interface ThrowingAction {
        void run() throws Exception;
    }

    private static final class InMemoryStore implements RiskMethodSelectionPolicyStore {
        private final Map<Integer, RbvmRiskMethodSelectionPolicy> byRevision = new LinkedHashMap<>();
        private final Map<String, RbvmRiskMethodSelectionPolicy> bySha = new LinkedHashMap<>();

        @Override
        public RiskMethodSelectionPolicyInstallResult install(RbvmRiskMethodSelectionPolicy policy) {
            RbvmRiskMethodSelectionPolicy existing = byRevision.get(policy.revision());
            if (existing != null) {
                RiskMethodSelectionPolicyInstallResult.Status status =
                        existing.policySha256().equals(policy.policySha256())
                                ? RiskMethodSelectionPolicyInstallResult.Status.REPLAYED
                                : RiskMethodSelectionPolicyInstallResult.Status.REVISION_CONFLICT;
                return new RiskMethodSelectionPolicyInstallResult(
                        status,
                        policy.revision(),
                        policy.policySha256(),
                        existing.revision(),
                        existing.policySha256()
                );
            }
            byRevision.put(policy.revision(), policy);
            bySha.put(policy.policySha256(), policy);
            return new RiskMethodSelectionPolicyInstallResult(
                    RiskMethodSelectionPolicyInstallResult.Status.INSERTED,
                    policy.revision(),
                    policy.policySha256(),
                    policy.revision(),
                    policy.policySha256()
            );
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicy> findByRevision(int revision) {
            return Optional.ofNullable(byRevision.get(revision));
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicy> findByPolicySha256(String policySha256) {
            return Optional.ofNullable(bySha.get(policySha256));
        }

        int size() {
            return byRevision.size();
        }
    }
}
