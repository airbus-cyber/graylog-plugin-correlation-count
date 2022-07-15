package com.airbus_cyber_security.graylog.events.processor.correlation.checks;

import com.google.common.collect.ImmutableList;
import org.graylog.events.processor.aggregation.AggregationKeyResult;
import org.graylog.events.processor.aggregation.AggregationResult;
import org.graylog.events.processor.aggregation.AggregationSeriesValue;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class CorrelationCountResults {

    private final Map<String, ImmutableList<String>> groupingFields;
    private final Map<String, Long> firstStreamCounts;
    private final Map<String, Long> secondStreamCounts;

    CorrelationCountResults() {
        this.groupingFields = new HashMap<>();
        this.firstStreamCounts = new HashMap<>();
        this.secondStreamCounts = new HashMap<>();
    }

    private String buildTermKey(ImmutableList<String> groupByFields) {
        StringBuilder builder = new StringBuilder();
        for (String field: groupByFields) {
            if (0 < builder.length()) {
                builder.append(" - ");
            }
            builder.append(field);
        }
        return builder.toString();
    }

    void addFirstStreamResult(ImmutableList<String> groupByFields, long count) {
        String key = buildTermKey(groupByFields);

        this.groupingFields.put(key, groupByFields);
        if (this.firstStreamCounts.containsKey(key)) {
            throw new IllegalArgumentException("Unexpected duplicated key in stream: " + key);
        }
        this.firstStreamCounts.put(key, count);
    }

    void addSecondStreamResult(ImmutableList<String> groupByFields, long count) {
        String key = buildTermKey(groupByFields);

        this.groupingFields.put(key, groupByFields);
        if (this.secondStreamCounts.containsKey(key)) {
            throw new IllegalArgumentException("Unexpected duplicated key in stream: " + key);
        }
        this.secondStreamCounts.put(key, count);
    }

    Collection<CorrelationCountResult> getAll() {
        ImmutableList.Builder<CorrelationCountResult> results = ImmutableList.builder();
        for (String key: groupingFields.keySet()) {
            ImmutableList<String> groupByFields = groupingFields.get(key);
            long firstStreamCount = firstStreamCounts.getOrDefault(key, 0L);
            long secondStreamCount = secondStreamCounts.getOrDefault(key, 0L);
            CorrelationCountResult result = new CorrelationCountResult(groupByFields, firstStreamCount, secondStreamCount);
            results.add(result);
        }

        return results.build();
    }
}
