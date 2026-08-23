package io.rbvm.decision;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Immutable tenant-scoped policy selecting exactly one primary risk methodology identity.
 *
 * <p>This contract does not evaluate risk, choose evidence, infer a default methodology, average
 * multiple methodology results, or derive Priority, Treatment, SLA, or remediation workflow. A
 * downstream decision must carry an exact policy revision/SHA and therefore an exact selected
 * method family, ID, version, and SHA.</p>
 */
public final class RbvmRiskMethodSelectionPolicy {
    public static final String ID = "RBVM_RISK_METHOD_SELECTION_POLICY_V1";
    public static final String SEMANTICS =
            "TENANT_SCOPED_EXPLICIT_PRIMARY_RISK_METHOD_EXACT_IDENTITY";
    public static final String CANONICAL_PAYLOAD_FORMAT =
            "RBVM_RISK_METHOD_SELECTION_POLICY_CANONICAL_BINARY_V1";

    public enum SelectionRole {
        PRIMARY
    }

    public enum MethodFamily {
        RBVM_FORMULA,
        STANDARD_DERIVED
    }

    private final String contractId;
    private final int revision;
    private final String policySha256;
    private final SelectionRole selectionRole;
    private final MethodFamily methodFamily;
    private final String methodId;
    private final int methodVersion;
    private final String methodSha256;

    private RbvmRiskMethodSelectionPolicy(
            String contractId,
            int revision,
            String policySha256,
            SelectionRole selectionRole,
            MethodFamily methodFamily,
            String methodId,
            int methodVersion,
            String methodSha256
    ) {
        this.contractId = requireExact(contractId, ID, "contractId");
        if (revision < 1) {
            throw new IllegalArgumentException("revision must be positive");
        }
        this.revision = revision;
        this.selectionRole = Objects.requireNonNull(selectionRole, "selectionRole");
        this.methodFamily = Objects.requireNonNull(methodFamily, "methodFamily");
        this.methodId = requireText(methodId, "methodId");
        if (methodVersion < 1) {
            throw new IllegalArgumentException("methodVersion must be positive");
        }
        this.methodVersion = methodVersion;
        this.methodSha256 = requireSha256(methodSha256, "methodSha256");
        this.policySha256 = requireSha256(policySha256, "policySha256");

        String expectedSha256 = canonicalSha256(
                this.contractId,
                this.revision,
                this.selectionRole,
                this.methodFamily,
                this.methodId,
                this.methodVersion,
                this.methodSha256
        );
        if (!this.policySha256.equals(expectedSha256)) {
            throw new IllegalArgumentException(
                    "policySha256 does not match the canonical risk method selection payload");
        }
    }

    /** Creates a policy selecting the accepted RBVM Formula V1 exact identity. */
    public static RbvmRiskMethodSelectionPolicy formulaV1(int revision) {
        return create(
                revision,
                SelectionRole.PRIMARY,
                MethodFamily.RBVM_FORMULA,
                RbvmFormulaV1.FORMULA_ID,
                RbvmFormulaV1.FORMULA_VERSION,
                RbvmFormulaV1.FORMULA_SHA256
        );
    }

    /** Creates a policy selecting one exact implemented standard-derived methodology definition. */
    public static RbvmRiskMethodSelectionPolicy derived(
            int revision,
            RbvmDerivedRiskMethodology.Definition definition
    ) {
        Objects.requireNonNull(definition, "definition");
        if (definition.classification() != RbvmDerivedRiskMethodology.Classification.STANDARD_DERIVED) {
            throw new IllegalArgumentException(
                    "Risk method selection V1 only accepts STANDARD_DERIVED external methodologies");
        }
        RbvmRiskMethodSelectionPolicy policy = create(
                revision,
                SelectionRole.PRIMARY,
                MethodFamily.STANDARD_DERIVED,
                definition.methodologyId(),
                definition.version(),
                definition.methodologySha256()
        );
        policy.requireCatalogBound();
        return policy;
    }

    /**
     * Rehydrates a persisted immutable policy. This verifies canonical identity but deliberately does
     * not require the selected method to remain present in the current executable catalog, so
     * historical policy provenance can still be read after a future catalog change.
     */
    public static RbvmRiskMethodSelectionPolicy rehydrate(
            String contractId,
            int revision,
            String policySha256,
            SelectionRole selectionRole,
            MethodFamily methodFamily,
            String methodId,
            int methodVersion,
            String methodSha256
    ) {
        return new RbvmRiskMethodSelectionPolicy(
                contractId,
                revision,
                policySha256,
                selectionRole,
                methodFamily,
                methodId,
                methodVersion,
                methodSha256
        );
    }

    /**
     * Fails closed unless this exact method identity is implemented in the current executable
     * catalog. Persistence installation calls this before accepting a new policy revision.
     */
    public void requireCatalogBound() {
        if (methodFamily == MethodFamily.RBVM_FORMULA) {
            if (!methodId.equals(RbvmFormulaV1.FORMULA_ID)
                    || methodVersion != RbvmFormulaV1.FORMULA_VERSION
                    || !methodSha256.equals(RbvmFormulaV1.FORMULA_SHA256)) {
                throw new IllegalArgumentException(
                        "RBVM_FORMULA selection does not match the accepted Formula V1 identity");
            }
            return;
        }

        RbvmDerivedRiskMethodology methodology = RbvmDerivedRiskMethodologyCatalog.find(methodId)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Selected derived methodology is not implemented: " + methodId));
        RbvmDerivedRiskMethodology.Definition definition = methodology.definition();
        if (!methodId.equals(definition.methodologyId())
                || methodVersion != definition.version()
                || !methodSha256.equals(definition.methodologySha256())) {
            throw new IllegalArgumentException(
                    "Selected derived methodology identity does not match the executable catalog");
        }
    }

    public String contractId() {
        return contractId;
    }

    public int revision() {
        return revision;
    }

    public String policySha256() {
        return policySha256;
    }

    public SelectionRole selectionRole() {
        return selectionRole;
    }

    public MethodFamily methodFamily() {
        return methodFamily;
    }

    public String methodId() {
        return methodId;
    }

    public int methodVersion() {
        return methodVersion;
    }

    public String methodSha256() {
        return methodSha256;
    }

    public String semantics() {
        return SEMANTICS;
    }

    public byte[] canonicalPayload() {
        return canonicalPayload(
                contractId,
                revision,
                selectionRole,
                methodFamily,
                methodId,
                methodVersion,
                methodSha256
        );
    }

    private static RbvmRiskMethodSelectionPolicy create(
            int revision,
            SelectionRole selectionRole,
            MethodFamily methodFamily,
            String methodId,
            int methodVersion,
            String methodSha256
    ) {
        String sha256 = canonicalSha256(
                ID,
                revision,
                selectionRole,
                methodFamily,
                methodId,
                methodVersion,
                methodSha256
        );
        return new RbvmRiskMethodSelectionPolicy(
                ID,
                revision,
                sha256,
                selectionRole,
                methodFamily,
                methodId,
                methodVersion,
                methodSha256
        );
    }

    private static String canonicalSha256(
            String contractId,
            int revision,
            SelectionRole selectionRole,
            MethodFamily methodFamily,
            String methodId,
            int methodVersion,
            String methodSha256
    ) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(canonicalPayload(
                    contractId,
                    revision,
                    selectionRole,
                    methodFamily,
                    methodId,
                    methodVersion,
                    methodSha256
            )));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", exception);
        }
    }

    private static byte[] canonicalPayload(
            String contractId,
            int revision,
            SelectionRole selectionRole,
            MethodFamily methodFamily,
            String methodId,
            int methodVersion,
            String methodSha256
    ) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                writeText(output, contractId);
                output.writeInt(revision);
                writeText(output, SEMANTICS);
                writeText(output, selectionRole.name());
                writeText(output, methodFamily.name());
                writeText(output, methodId);
                output.writeInt(methodVersion);
                writeText(output, methodSha256);
            }
            return bytes.toByteArray();
        } catch (IOException exception) {
            throw new IllegalStateException("Could not canonicalize risk method selection policy", exception);
        }
    }

    private static void writeText(DataOutputStream output, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        output.writeInt(bytes.length);
        output.write(bytes);
    }

    private static String requireExact(String value, String expected, String field) {
        if (!expected.equals(value)) {
            throw new IllegalArgumentException(field + " must equal " + expected);
        }
        return value;
    }

    private static String requireText(String value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank() || !value.equals(value.trim())) {
            throw new IllegalArgumentException(field + " must be non-blank canonical text");
        }
        return value;
    }

    private static String requireSha256(String value, String field) {
        Objects.requireNonNull(value, field);
        if (!value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256 hex");
        }
        return value;
    }
}
