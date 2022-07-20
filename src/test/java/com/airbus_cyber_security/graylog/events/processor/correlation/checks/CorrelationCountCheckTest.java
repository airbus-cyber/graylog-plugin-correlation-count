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
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.joda.time.DateTime;
import org.junit.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import static org.junit.Assert.assertTrue;

public class CorrelationCountCheckTest {

    @Test
    public void testCheckOrderStreamThreshold2After() {
        List<MessageSummary> summariesStream1 = new ArrayList<MessageSummary>();
        summariesStream1.add(new MessageSummary("0", new Message("message", "source", new DateTime(600))));
        summariesStream1.add(new MessageSummary("1", new Message("message", "source", new DateTime(1100))));

        List<MessageSummary> summariesStream2 = new ArrayList<MessageSummary>();
        summariesStream2.add(new MessageSummary("0", new Message("message", "source", new DateTime(100))));
        summariesStream2.add(new MessageSummary("1", new Message("message", "source", new DateTime(200))));
        summariesStream2.add(new MessageSummary("2", new Message("message", "source", new DateTime(300))));
        summariesStream2.add(new MessageSummary("3", new Message("message", "source", new DateTime(400))));
        summariesStream2.add(new MessageSummary("4", new Message("message", "source", new DateTime(500))));
        summariesStream2.add(new MessageSummary("5", new Message("message", "source", new DateTime(700))));
        summariesStream2.add(new MessageSummary("6", new Message("message", "source", new DateTime(800))));
        summariesStream2.add(new MessageSummary("7", new Message("message", "source", new DateTime(900))));
        summariesStream2.add(new MessageSummary("8", new Message("message", "source", new DateTime(1000))));

        CorrelationCountProcessorConfig configuration = CorrelationCountProcessorConfig.builder()
                .stream("main stream")
                .additionalStream("additional stream")
                .additionalThresholdType("MORE")
                .additionalThreshold(1)
                .thresholdType("MORE")
                .threshold(4)
                .messagesOrder("AFTER")
                .searchWithinMs(10 * 60 * 1000)
                .executeEveryMs(0)
                .groupingFields(new ArrayList<>())
                .comment("test comment")
                .searchQuery("*")
                .build();

        CorrelationCountCheck subject = new CorrelationCountCheck(configuration, "AFTER");
        assertTrue(subject.isRuleTriggered(summariesStream2, summariesStream1));
    }
}
