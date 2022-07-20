package com.airbus_cyber_security.graylog.events.processor.correlation.checks;

public enum OrderType {

    ANY("ANY"),
    BEFORE("BEFORE"),
    AFTER("AFTER");

    private final String description;

    OrderType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public static OrderType fromString(String text) {
        for (OrderType orderType : OrderType.values()) {
            if (orderType.description.equals(text)) {
                return orderType;
            }
        }
        throw new IllegalArgumentException("Unknown OrderType value: " + text);
    }
}
