package io.rbvm.postgres;

import java.util.ArrayList;
import java.util.List;

final class SqlScriptParser {
    private SqlScriptParser() {
    }

    static List<String> statements(String script) {
        List<String> output = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        State state = State.NORMAL;
        int blockDepth = 0;
        String dollarDelimiter = null;
        for (int index = 0; index < script.length(); index++) {
            char value = script.charAt(index);
            char next = index + 1 < script.length() ? script.charAt(index + 1) : '\0';
            current.append(value);
            switch (state) {
                case NORMAL -> {
                    if (value == '\'' ) {
                        state = State.SINGLE_QUOTE;
                    } else if (value == '"') {
                        state = State.DOUBLE_QUOTE;
                    } else if (value == '-' && next == '-') {
                        current.append(next);
                        index++;
                        state = State.LINE_COMMENT;
                    } else if (value == '/' && next == '*') {
                        current.append(next);
                        index++;
                        blockDepth = 1;
                        state = State.BLOCK_COMMENT;
                    } else if (value == '$') {
                        String delimiter = dollarDelimiterAt(script, index);
                        if (delimiter != null) {
                            current.append(delimiter, 1, delimiter.length());
                            index += delimiter.length() - 1;
                            dollarDelimiter = delimiter;
                            state = State.DOLLAR_QUOTE;
                        }
                    } else if (value == ';') {
                        addStatement(output, current);
                    }
                }
                case SINGLE_QUOTE -> {
                    if (value == '\'' && next == '\'') {
                        current.append(next);
                        index++;
                    } else if (value == '\'') {
                        state = State.NORMAL;
                    }
                }
                case DOUBLE_QUOTE -> {
                    if (value == '"' && next == '"') {
                        current.append(next);
                        index++;
                    } else if (value == '"') {
                        state = State.NORMAL;
                    }
                }
                case LINE_COMMENT -> {
                    if (value == '\n') {
                        state = State.NORMAL;
                    }
                }
                case BLOCK_COMMENT -> {
                    if (value == '/' && next == '*') {
                        current.append(next);
                        index++;
                        blockDepth++;
                    } else if (value == '*' && next == '/') {
                        current.append(next);
                        index++;
                        blockDepth--;
                        if (blockDepth == 0) {
                            state = State.NORMAL;
                        }
                    }
                }
                case DOLLAR_QUOTE -> {
                    if (script.startsWith(dollarDelimiter, index)) {
                        current.append(dollarDelimiter, 1, dollarDelimiter.length());
                        index += dollarDelimiter.length() - 1;
                        dollarDelimiter = null;
                        state = State.NORMAL;
                    }
                }
            }
        }
        if (state != State.NORMAL && state != State.LINE_COMMENT) {
            throw new IllegalArgumentException("SQL script contains an unterminated lexical construct");
        }
        addStatement(output, current);
        return List.copyOf(output);
    }

    private static String dollarDelimiterAt(String script, int offset) {
        int end = script.indexOf('$', offset + 1);
        if (end < 0) {
            return null;
        }
        for (int index = offset + 1; index < end; index++) {
            char value = script.charAt(index);
            if (!(Character.isLetterOrDigit(value) || value == '_')) {
                return null;
            }
        }
        return script.substring(offset, end + 1);
    }

    private static void addStatement(List<String> output, StringBuilder current) {
        String value = current.toString().trim();
        current.setLength(0);
        if (value.endsWith(";")) {
            value = value.substring(0, value.length() - 1).trim();
        }
        if (!value.isEmpty()
                && !value.equalsIgnoreCase("BEGIN")
                && !value.equalsIgnoreCase("COMMIT")) {
            output.add(value);
        }
    }

    private enum State {
        NORMAL,
        SINGLE_QUOTE,
        DOUBLE_QUOTE,
        LINE_COMMENT,
        BLOCK_COMMENT,
        DOLLAR_QUOTE
    }
}
