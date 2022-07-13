package com.airbus_cyber_security.graylog.events.processor.correlation.checks;

public class CorrelationCountResult {

    private final long firstStreamCount;
    private final long secondStreamCount;

    // TODO should have the timestamp and the group fields (as an Immutable list)
    public CorrelationCountResult(long firstStreamCount, long secondStreamCount) {
        this.firstStreamCount = firstStreamCount;
        this.secondStreamCount = secondStreamCount;
    }

    public long getFirstStreamCount() {
        return this.firstStreamCount;
    }

    public long getSecondStreamCount() {
        return this.secondStreamCount;
    }
}
