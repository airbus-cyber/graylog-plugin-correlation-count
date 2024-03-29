/*
 * Copyright (C) 2018 Airbus CyberSecurity (SAS)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */

package com.airbus_cyber_security.graylog.events.processor.correlation.checks;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum OrderType {

    // TODO try to avoid repeating string "ANY". Would it work with enums without values? Otherwise use some constants.
    @JsonProperty("ANY")
    ANY("ANY"),
    
    @JsonProperty("BEFORE")
    BEFORE("BEFORE"),
    
    @JsonProperty("AFTER")
    AFTER("AFTER");

    private final String description;

    OrderType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public static OrderType fromString(String text) {
        for (OrderType orderType: OrderType.values()) {
            if (orderType.description.equals(text)) {
                return orderType;
            }
        }
        throw new IllegalArgumentException("Unknown OrderType value: " + text);
    }
}
