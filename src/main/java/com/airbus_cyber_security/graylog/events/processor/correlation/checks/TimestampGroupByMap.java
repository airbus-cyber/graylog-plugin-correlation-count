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

import org.joda.time.DateTime;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class TimestampGroupByMap<V> {

    private final Map<DateTime, Map<String, V>> map;

    TimestampGroupByMap() {
        this.map = new HashMap<>();
    }

    void put(DateTime timestamp, String groupBy, V value) {
        Map<String, V> values = this.map.computeIfAbsent(timestamp, k -> new HashMap<>());
        values.put(groupBy, value);
    }

    Set<DateTime> getTimestamps() {
        return this.map.keySet();
    }

    Set<String> getGroupByFields(DateTime timestamp) {
        Map<String, V> values = this.map.get(timestamp);
        return values.keySet();
    }

    V get(DateTime timestamp, String groupBy) {
        Map<String, V> values = this.map.get(timestamp);
        return values.get(groupBy);
    }

    boolean containsKey(DateTime timestamp, String groupBy) {
        Map<String, V> values = this.map.get(timestamp);
        if (values == null) {
            return false;
        }
        return values.containsKey(groupBy);
    }

    V getOrDefault(DateTime timestamp, String groupBy, V defaultValue) {
        Map<String, V> values = this.map.get(timestamp);
        if (values == null) {
            return defaultValue;
        }
        return values.getOrDefault(groupBy, defaultValue);
    }
}
