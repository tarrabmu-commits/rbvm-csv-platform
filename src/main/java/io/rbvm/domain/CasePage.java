package io.rbvm.domain;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public record CasePage(
        long catalogRevision,
        CatalogSnapshot summary,
        List<Map<String, Object>> cases,
        String nextCursor
) {
    public CasePage {
        cases = List.copyOf(cases);
    }

    public Map<String, Object> toMap() {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("catalogRevision", catalogRevision);
        output.put("summary", summary.toMap());
        output.put("cases", cases);
        output.put("nextCursor", nextCursor);
        return output;
    }
}
