package io.rbvm.csv;

import java.nio.file.Files;
import java.nio.file.Path;

public final class CsvContractCli {
    private CsvContractCli() {
    }

    public static void main(String[] args) {
        if (args.length < 1 || args.length > 3) {
            System.err.println("Usage: CsvContractCli <csv-path> [source-profile-id] [preview-limit]");
            System.exit(64);
        }

        Path path = Path.of(args[0]).toAbsolutePath().normalize();
        String sourceProfile = args.length >= 2 ? args[1] : "default-wazuh-csv";
        int previewLimit = args.length == 3 ? Integer.parseInt(args[2]) : 5;

        if (!Files.isRegularFile(path)) {
            System.err.println("CSV file not found: " + path);
            System.exit(66);
        }

        try {
            AnalysisReport report = new WazuhCsvAnalyzer(sourceProfile).analyze(path, previewLimit);
            System.out.print(JsonOutput.pretty(report.toMap()));
        } catch (Exception exception) {
            System.err.println(JsonOutput.pretty(java.util.Map.of(
                    "contractId", CsvContractV1.ID,
                    "status", "REJECTED",
                    "error", exception.getMessage() == null ? exception.getClass().getSimpleName() : exception.getMessage()
            )));
            System.exit(65);
        }
    }
}

