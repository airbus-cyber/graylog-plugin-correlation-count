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
