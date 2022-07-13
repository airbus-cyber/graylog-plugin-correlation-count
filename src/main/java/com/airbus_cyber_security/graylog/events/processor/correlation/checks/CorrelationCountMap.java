package com.airbus_cyber_security.graylog.events.processor.correlation.checks;

import java.util.HashMap;
import java.util.Map;

public class CorrelationCountMap {

    // TODO change Long[] into a new type CorrelationResult which will contain the timestamp, group by fields, first stream count and second stream count
    private final Map<String, CorrelationCountResult> results;

    public CorrelationCountMap() {
        this.results = new HashMap<>();
    }

    private void setResult(String groupByFields, long firstStreamCount, long secondStreamCount) {
        CorrelationCountResult result = new CorrelationCountResult(firstStreamCount, secondStreamCount);
        this.results.put(groupByFields, result);
    }

    // TODO add timestamp, change time of groupByFields to ImmutableList<String>
    public void addFirstStreamCount(String groupByFields, long firstStreamCount) {
        long secondStreamCount = 0L;
        this.setResult(groupByFields, firstStreamCount, secondStreamCount);
    }

    // TODO add timestamp, change time of groupByFields to ImmutableList<String>
    public void addSecondStreamCount(String groupByFields, long secondStreamCount) {
        long firstStreamCount = 0L;
        CorrelationCountResult previousResult = this.results.get(groupByFields);
        if (previousResult != null) {
            firstStreamCount = previousResult.getFirstStreamCount();
        }
        this.setResult(groupByFields, firstStreamCount, secondStreamCount);
    }

    public Map<String, CorrelationCountResult> getResults() {
        return this.results;
    }
}