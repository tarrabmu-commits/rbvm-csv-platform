package io.rbvm.csv;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

public final class JsonOutput {
    private JsonOutput() {
    }

    /** Compatibility alias for transports that need deterministic JSON bytes. */
    public static String object(Object value) {
        return pretty(value);
    }

    public static String pretty(Object value) {
        StringBuilder output = new StringBuilder();
        write(value, output, 0);
        output.append('\n');
        return output.toString();
    }

    private static void write(Object value, StringBuilder output, int depth) {
        if (value == null) {
            output.append("null");
        } else if (value instanceof String text) {
            quote(text, output);
        } else if (value instanceof Number || value instanceof Boolean) {
            output.append(value);
        } else if (value instanceof Map<?, ?> map) {
            writeMap(map, output, depth);
        } else if (value instanceof List<?> list) {
            writeList(list, output, depth);
        } else {
            quote(value.toString(), output);
        }
    }

    private static void writeMap(Map<?, ?> map, StringBuilder output, int depth) {
        output.append('{');
        if (!map.isEmpty()) {
            output.append('\n');
            Iterator<? extends Map.Entry<?, ?>> iterator = map.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<?, ?> entry = iterator.next();
                indent(output, depth + 1);
                quote(String.valueOf(entry.getKey()), output);
                output.append(": ");
                write(entry.getValue(), output, depth + 1);
                if (iterator.hasNext()) {
                    output.append(',');
                }
                output.append('\n');
            }
            indent(output, depth);
        }
        output.append('}');
    }

    private static void writeList(List<?> list, StringBuilder output, int depth) {
        output.append('[');
        if (!list.isEmpty()) {
            output.append('\n');
            for (int i = 0; i < list.size(); i++) {
                indent(output, depth + 1);
                write(list.get(i), output, depth + 1);
                if (i + 1 < list.size()) {
                    output.append(',');
                }
                output.append('\n');
            }
            indent(output, depth);
        }
        output.append(']');
    }

    private static void quote(String value, StringBuilder output) {
        output.append('"');
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '"' -> output.append("\\\"");
                case '\\' -> output.append("\\\\");
                case '\b' -> output.append("\\b");
                case '\f' -> output.append("\\f");
                case '\n' -> output.append("\\n");
                case '\r' -> output.append("\\r");
                case '\t' -> output.append("\\t");
                default -> {
                    if (ch < 0x20) {
                        output.append(String.format("\\u%04x", (int) ch));
                    } else {
                        output.append(ch);
                    }
                }
            }
        }
        output.append('"');
    }

    private static void indent(StringBuilder output, int depth) {
        output.append("  ".repeat(depth));
    }
}
