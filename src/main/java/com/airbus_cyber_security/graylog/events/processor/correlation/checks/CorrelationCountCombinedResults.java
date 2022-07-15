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
import org.joda.time.DateTime;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class CorrelationCountCombinedResults {

    private final Map<String, ImmutableList<String>> groupingFields;
    private final Map<String, Long> firstStreamCounts;
    private final Map<String, Long> secondStreamCounts;

    CorrelationCountCombinedResults() {
        this.groupingFields = new HashMap<>();
        this.firstStreamCounts = new HashMap<>();
        this.secondStreamCounts = new HashMap<>();
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

    void addFirstStreamResult(DateTime timestamp, ImmutableList<String> groupByFields, long count) {
        String key = buildTermKey(groupByFields);

        this.groupingFields.put(key, groupByFields);
        if (this.firstStreamCounts.containsKey(key)) {
            throw new IllegalArgumentException("Unexpected duplicated key in stream: " + key);
        }
        this.firstStreamCounts.put(key, count);
    }

    void addSecondStreamResult(DateTime timestamp, ImmutableList<String> groupByFields, long count) {
        String key = buildTermKey(groupByFields);

        this.groupingFields.put(key, groupByFields);
        if (this.secondStreamCounts.containsKey(key)) {
            throw new IllegalArgumentException("Unexpected duplicated key in stream: " + key);
        }
        this.secondStreamCounts.put(key, count);
    }

    Collection<CorrelationCountResult> getAll() {
        ImmutableList.Builder<CorrelationCountResult> results = ImmutableList.builder();
        for (String key: groupingFields.keySet()) {
            ImmutableList<String> groupByFields = groupingFields.get(key);
            long firstStreamCount = firstStreamCounts.getOrDefault(key, 0L);
            long secondStreamCount = secondStreamCounts.getOrDefault(key, 0L);
            CorrelationCountResult result = new CorrelationCountResult(groupByFields, firstStreamCount, secondStreamCount);
            results.add(result);
        }

        return results.build();
    }
}
