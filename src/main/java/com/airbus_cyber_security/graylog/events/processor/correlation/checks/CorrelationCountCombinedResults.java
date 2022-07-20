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

public class CorrelationCountCombinedResults {

    private final TimestampGroupByMap<ImmutableList<String>> groupingFields;
    private final TimestampGroupByMap<Long> firstStreamCounts;
    private final TimestampGroupByMap<Long> secondStreamCounts;

    CorrelationCountCombinedResults() {
        this.groupingFields = new TimestampGroupByMap<>();
        this.firstStreamCounts = new TimestampGroupByMap<>();
        this.secondStreamCounts = new TimestampGroupByMap<>();
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

        this.groupingFields.put(timestamp, key, groupByFields);
        if (this.firstStreamCounts.containsKey(timestamp, key)) {
            throw new IllegalArgumentException("Unexpected duplicated key in stream: " + timestamp + ", " + key);
        }
        this.firstStreamCounts.put(timestamp, key, count);
    }

    void addSecondStreamResult(DateTime timestamp, ImmutableList<String> groupByFields, long count) {
        String key = buildTermKey(groupByFields);

        this.groupingFields.put(timestamp, key, groupByFields);
        if (this.secondStreamCounts.containsKey(timestamp, key)) {
            throw new IllegalArgumentException("Unexpected duplicated key in additional stream: " + timestamp + ", " + key);
        }
        this.secondStreamCounts.put(timestamp, key, count);
    }

    Collection<CorrelationCountResult> getAll() {
        ImmutableList.Builder<CorrelationCountResult> results = ImmutableList.builder();
        for (DateTime timestamp: this.groupingFields.getTimestamps()) {
            for (String key: this.groupingFields.getGroupByFields(timestamp)) {
                ImmutableList<String> groupByFields = this.groupingFields.get(timestamp, key);
                long firstStreamCount = this.firstStreamCounts.getOrDefault(timestamp, key, 0L);
                long secondStreamCount = this.secondStreamCounts.getOrDefault(timestamp, key, 0L);
                CorrelationCountResult result = new CorrelationCountResult(timestamp, groupByFields, firstStreamCount, secondStreamCount);
                results.add(result);
            }
        }

        return results.build();
    }
}
