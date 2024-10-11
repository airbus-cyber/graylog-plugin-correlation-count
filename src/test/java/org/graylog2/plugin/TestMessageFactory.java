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
package org.graylog2.plugin;

import org.joda.time.DateTime;

import java.util.Map;

public class TestMessageFactory implements MessageFactory {

    public Message createMessage(String message, String source, DateTime timestamp) {
        return new Message(message, source, timestamp);
    }

    public Message createMessage(Map<String, Object> fields) {
        return new Message(fields);
    }

    public Message createMessage(String id, Map<String, Object> newFields) {
        return new Message(id, newFields);
    }
}
