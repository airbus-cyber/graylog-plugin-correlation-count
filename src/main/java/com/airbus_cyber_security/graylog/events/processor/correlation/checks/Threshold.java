package com.airbus_cyber_security.graylog.events.processor.correlation.checks;

public class Threshold {

    private final ThresholdType type;
    private final int value;

    public Threshold(String type, int value) {
        this.type = ThresholdType.fromString(type);
        this.value = value;
    }

    public boolean isReached(long count) {
        return (((this.type == ThresholdType.MORE) && (count > this.value)) ||
                ((this.type == ThresholdType.LESS) && (count < this.value)));
    }
}
