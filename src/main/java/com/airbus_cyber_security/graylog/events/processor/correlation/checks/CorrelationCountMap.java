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

import com.google.common.collect.ImmutableList;
import org.graylog.events.processor.aggregation.AggregationKeyResult;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class CorrelationCountMap {

    // TODO: should distinguish by timestamps too!!
    private final Map<String, CorrelationCountResult> results;

    public CorrelationCountMap() {
        this.results = new HashMap<>();
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

    private void setResult(String key, ImmutableList<String> groupByFields, long firstStreamCount, long secondStreamCount) {
        CorrelationCountResult result = new CorrelationCountResult(groupByFields, firstStreamCount, secondStreamCount);
        this.results.put(key, result);
    }

    // TODO add timestamp, change type of groupByFields to ImmutableList<String>
    public void addFirstStreamCount(ImmutableList<String> groupByFields, long firstStreamCount) {
        String key = buildTermKey(groupByFields);
        long secondStreamCount = 0L;
        this.setResult(key, groupByFields, firstStreamCount, secondStreamCount);
    }

    // TODO add timestamp, change type of groupByFields to ImmutableList<String>
    public void addSecondStreamCount(ImmutableList<String> groupByFields, long secondStreamCount) {
        String key = buildTermKey(groupByFields);
        long firstStreamCount = 0L;
        CorrelationCountResult previousResult = this.results.get(key);
        if (previousResult != null) {
            firstStreamCount = previousResult.getFirstStreamCount();
        }
        this.setResult(key, groupByFields, firstStreamCount, secondStreamCount);
    }

    public Collection<CorrelationCountResult> getResults() {
        return this.results.values();
    }
}
