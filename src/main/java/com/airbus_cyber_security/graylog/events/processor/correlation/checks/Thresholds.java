package com.airbus_cyber_security.graylog.events.processor.correlation.checks;

import com.airbus_cyber_security.graylog.events.processor.correlation.CorrelationCountProcessorConfig;

public class Thresholds {

    private final Threshold mainStreamThreshold;
    private final Threshold additionalStreamThreshold;

    public Thresholds(CorrelationCountProcessorConfig configuration) {
        this.mainStreamThreshold = new Threshold(configuration.thresholdType(), configuration.threshold());
        this.additionalStreamThreshold = new Threshold(configuration.additionalThresholdType(), configuration.additionalThreshold());
    }

    public boolean areReached(long mainCount, long additionalCount) {
        return this.mainStreamThreshold.isReached(mainCount) && this.additionalStreamThreshold.isReached(additionalCount);
    }
}
