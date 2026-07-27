package io.rbvm.csv;

import java.io.Closeable;
import java.io.IOException;
import java.io.PushbackReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

/**
 * A dependency-free, streaming RFC 4180 reader used by the contract spike.
 * It deliberately preserves embedded CR/LF characters inside quoted fields.
 */
public final class Rfc4180CsvReader implements Closeable {
    private final PushbackReader reader;
    private long logicalRowNumber;
    private long physicalLineNumber = 1;

    public Rfc4180CsvReader(Reader reader) {
        this.reader = new PushbackReader(reader, 1);
    }

    public List<String> readRow() throws IOException {
        List<String> fields = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean inQuotes = false;
        boolean afterClosingQuote = false;
        boolean sawAnyCharacter = false;

        while (true) {
            int raw = reader.read();
            if (raw == -1) {
                if (inQuotes) {
                    throw syntax("Unexpected end of file inside a quoted field");
                }
                if (!sawAnyCharacter && fields.isEmpty() && field.isEmpty()) {
                    return null;
                }
                fields.add(field.toString());
                logicalRowNumber++;
                return List.copyOf(fields);
            }

            sawAnyCharacter = true;
            char ch = (char) raw;

            if (inQuotes) {
                if (ch == '"') {
                    int next = reader.read();
                    if (next == '"') {
                        field.append('"');
                    } else {
                        inQuotes = false;
                        afterClosingQuote = true;
                        if (next != -1) {
                            reader.unread(next);
                        }
                    }
                } else {
                    field.append(ch);
                    if (ch == '\n') {
                        physicalLineNumber++;
                    } else if (ch == '\r') {
                        countOptionalLfInsideQuotedField(field);
                    }
                }
                continue;
            }

            if (afterClosingQuote) {
                if (ch == ',') {
                    fields.add(field.toString());
                    field.setLength(0);
                    afterClosingQuote = false;
                } else if (ch == '\r' || ch == '\n') {
                    consumeRecordEnding(ch);
                    fields.add(field.toString());
                    logicalRowNumber++;
                    return List.copyOf(fields);
                } else {
                    throw syntax("Unexpected character after a closing quote: " + printable(ch));
                }
                continue;
            }

            if (ch == ',') {
                fields.add(field.toString());
                field.setLength(0);
            } else if (ch == '\r' || ch == '\n') {
                consumeRecordEnding(ch);
                fields.add(field.toString());
                logicalRowNumber++;
                return List.copyOf(fields);
            } else if (ch == '"') {
                if (!field.isEmpty()) {
                    throw syntax("Quote found in the middle of an unquoted field");
                }
                inQuotes = true;
            } else {
                field.append(ch);
            }
        }
    }

    private void consumeRecordEnding(char first) throws IOException {
        if (first == '\r') {
            int next = reader.read();
            if (next != '\n' && next != -1) {
                reader.unread(next);
            }
        }
        physicalLineNumber++;
    }

    private void countOptionalLfInsideQuotedField(StringBuilder field) throws IOException {
        int next = reader.read();
        if (next == '\n') {
            field.append('\n');
        } else if (next != -1) {
            reader.unread(next);
        }
        physicalLineNumber++;
    }

    private CsvContractException syntax(String message) {
        return new CsvContractException(message + " at logical row "
                + (logicalRowNumber + 1) + ", physical line " + physicalLineNumber);
    }

    private static String printable(char ch) {
        return Character.isISOControl(ch) ? "U+" + String.format("%04X", (int) ch) : "'" + ch + "'";
    }

    @Override
    public void close() throws IOException {
        reader.close();
    }
}

