package io.rbvm.decision;

import io.rbvm.decision.RbvmDerivedRiskMethodology.Evaluation;
import io.rbvm.decision.RbvmDerivedRiskMethodology.Measure;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Deterministic canonical identity for one externally-derived RBVM methodology evaluation.
 *
 * <p>This is deliberately distinct from {@link RbvmFormulaV1Explanation}. Formula V1 has an
 * accepted historical canonical explanation contract; OWASP/Microsoft-derived evaluations must
 * not be forced into that Formula-specific representation. This payload binds the exact Decision
 * Input V3 snapshot identity to the exact derived methodology definition and result semantics so a
 * later append-only persistence/replay layer can use an unambiguous immutable identity.</p>
 */
public final class RbvmDerivedRiskCanonicalResult {
    public static final String PAYLOAD_FORMAT =
            "RBVM_DERIVED_RISK_RESULT_CANONICAL_BINARY_V1";
    public static final int FORMAT_VERSION = 1;

    private final Evaluation evaluation;
    private final List<Measure> canonicalMeasures;
    private final byte[] canonicalPayload;
    private final String canonicalSha256;

    private RbvmDerivedRiskCanonicalResult(
            Evaluation evaluation,
            List<Measure> canonicalMeasures,
            byte[] canonicalPayload,
            String canonicalSha256
    ) {
        this.evaluation = evaluation;
        this.canonicalMeasures = List.copyOf(canonicalMeasures);
        this.canonicalPayload = canonicalPayload.clone();
        this.canonicalSha256 = canonicalSha256;
    }

    public static RbvmDerivedRiskCanonicalResult from(Evaluation evaluation) {
        Objects.requireNonNull(evaluation, "evaluation");
        if (!RbvmDecisionInputSnapshot.V3_ID.equals(evaluation.inputContractId())) {
            throw new IllegalArgumentException(
                    "Derived risk canonical results require RBVM_DECISION_INPUT_SNAPSHOT_V3"
            );
        }

        List<Measure> measures = canonicalMeasures(evaluation.measures());
        byte[] payload = canonicalPayload(evaluation, measures);
        return new RbvmDerivedRiskCanonicalResult(
                evaluation,
                measures,
                payload,
                sha256(payload)
        );
    }

    public Evaluation evaluation() {
        return evaluation;
    }

    public List<Measure> canonicalMeasures() {
        return canonicalMeasures;
    }

    public byte[] canonicalPayload() {
        return canonicalPayload.clone();
    }

    public String canonicalSha256() {
        return canonicalSha256;
    }

    private static List<Measure> canonicalMeasures(List<Measure> input) {
        Objects.requireNonNull(input, "measures");
        List<Measure> values = new ArrayList<>(input);
        values.sort(Comparator
                .comparing(Measure::measureId)
                .thenComparing(Measure::role)
                .thenComparing(Measure::scale)
                .thenComparing(value -> canonicalDecimal(value.value())));

        Set<String> ids = new HashSet<>();
        for (Measure value : values) {
            if (!ids.add(value.measureId())) {
                throw new IllegalArgumentException(
                        "Derived risk result contains duplicate measureId: " + value.measureId()
                );
            }
        }
        return List.copyOf(values);
    }

    private static byte[] canonicalPayload(Evaluation value, List<Measure> measures) {
        RbvmDerivedRiskMethodology.Definition definition = value.definition();
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream out = new DataOutputStream(bytes)) {
                writeString(out, PAYLOAD_FORMAT);
                out.writeInt(FORMAT_VERSION);

                writeString(out, definition.methodologyId());
                out.writeInt(definition.version());
                writeString(out, definition.classification().name());
                writeString(out, definition.provider());
                writeString(out, definition.sourceModel());
                writeString(out, definition.sourceEquation());
                writeString(out, definition.sourceUrl());
                writeString(out, definition.methodologySha256());
                writeString(out, definition.outputName());

                writeString(out, value.inputContractId());
                writeString(out, value.inputSnapshotSha256());
                out.writeLong(value.findingId().getMostSignificantBits());
                out.writeLong(value.findingId().getLeastSignificantBits());

                writeString(out, value.state().name());
                writeNullableString(out, value.reasonCode());
                writeNullableDecimal(out, value.numericScore());
                writeNullableString(out, value.numericScale());
                writeNullableString(out, value.rating());

                out.writeInt(measures.size());
                for (Measure measure : measures) {
                    writeString(out, measure.measureId());
                    writeString(out, measure.role());
                    writeString(out, canonicalDecimal(measure.value()));
                    writeString(out, measure.scale());
                }
            }
            return bytes.toByteArray();
        } catch (IOException exception) {
            throw new IllegalStateException("Could not canonicalize derived risk result", exception);
        }
    }

    private static void writeNullableDecimal(DataOutputStream out, BigDecimal value)
            throws IOException {
        if (value == null) {
            out.writeBoolean(false);
            return;
        }
        out.writeBoolean(true);
        writeString(out, canonicalDecimal(value));
    }

    private static void writeNullableString(DataOutputStream out, String value) throws IOException {
        if (value == null) {
            out.writeBoolean(false);
            return;
        }
        out.writeBoolean(true);
        writeString(out, value);
    }

    private static void writeString(DataOutputStream out, String value) throws IOException {
        Objects.requireNonNull(value, "canonical string");
        byte[] utf8 = value.getBytes(StandardCharsets.UTF_8);
        out.writeInt(utf8.length);
        out.write(utf8);
    }

    private static String canonicalDecimal(BigDecimal value) {
        return Objects.requireNonNull(value, "decimal").toPlainString();
    }

    private static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", exception);
        }
    }
}
