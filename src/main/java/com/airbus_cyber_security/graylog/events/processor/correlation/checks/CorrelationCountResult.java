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

public class CorrelationCountResult {

    private final long firstStreamCount;
    private final long secondStreamCount;

    // TODO should have the timestamp and the group fields (as an Immutable list)
    public CorrelationCountResult(long firstStreamCount, long secondStreamCount) {
        this.firstStreamCount = firstStreamCount;
        this.secondStreamCount = secondStreamCount;
    }

    public long getFirstStreamCount() {
        return this.firstStreamCount;
    }

    public long getSecondStreamCount() {
        return this.secondStreamCount;
    }
}
