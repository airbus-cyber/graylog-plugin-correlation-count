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

import java.util.HashMap;
import java.util.Map;

public class CorrelationCountMap {

    private final Map<String, CorrelationCountResult> results;

    public CorrelationCountMap() {
        this.results = new HashMap<>();
    }

    private void setResult(String groupByFields, long firstStreamCount, long secondStreamCount) {
        CorrelationCountResult result = new CorrelationCountResult(firstStreamCount, secondStreamCount);
        this.results.put(groupByFields, result);
    }

    // TODO add timestamp, change type of groupByFields to ImmutableList<String>
    public void addFirstStreamCount(String groupByFields, long firstStreamCount) {
        long secondStreamCount = 0L;
        this.setResult(groupByFields, firstStreamCount, secondStreamCount);
    }

    // TODO add timestamp, change type of groupByFields to ImmutableList<String>
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
