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
