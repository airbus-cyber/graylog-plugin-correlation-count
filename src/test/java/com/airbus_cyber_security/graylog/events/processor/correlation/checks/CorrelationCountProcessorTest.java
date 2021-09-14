/*
 * graylog-plugin-correlation-count Source Code
 * Copyright (C) 2018-2020 - Airbus CyberSecurity (SAS) - All rights reserved
 *
 * This file is part of the graylog-plugin-correlation-count GPL Source Code.
 *
 * graylog-plugin-correlation-count Source Code is free software:
 * you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this code.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.airbus_cyber_security.graylog.events.processor.correlation.checks;

import com.airbus_cyber_security.graylog.events.processor.correlation.CorrelationCountProcessor;
import com.airbus_cyber_security.graylog.events.processor.correlation.CorrelationCountProcessorConfig;
import com.airbus_cyber_security.graylog.events.processor.correlation.CorrelationCountProcessorParameters;
import com.google.common.collect.ImmutableList;
import org.graylog.events.event.EventFactory;
import org.graylog.events.notifications.EventNotificationSettings;
import org.graylog.events.processor.DBEventProcessorStateService;
import org.graylog.events.processor.EventDefinitionDto;
import org.graylog.events.processor.EventProcessorDependencyCheck;
import org.graylog.events.processor.EventProcessorPreconditionException;
import org.graylog.events.processor.aggregation.AggregationSearch;
import org.graylog.events.search.MoreSearch;
import org.graylog2.indexer.messages.Messages;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.Assert.assertEquals;

public class CorrelationCountProcessorTest {
    private final int threshold = 100;

    @Rule
    public final MockitoRule mockitoRule = MockitoJUnit.rule();

    @Mock
    private EventFactory eventFactory;
    @Mock
    private DBEventProcessorStateService stateService;
    @Mock
    private EventProcessorDependencyCheck eventProcessorDependencyCheck;
    @Mock
    private MoreSearch moreSearch;
    @Mock
    private Searches searches;
    @Mock
    private Messages messages;

    @Test
    public void testEvents() {
        final DateTime now = DateTime.now(DateTimeZone.UTC);
        final AbsoluteRange timeRange = AbsoluteRange.create(now.minusHours(1), now.plusHours(1));
        final EventDefinitionDto eventDefinitionDto = EventDefinitionDto.builder()
                .id("dto-id")
                .title("Test Correlation")
                .description("A test correlation event processors")
                .config(getCorrelationCountProcessorConfig())
                .alert(false)
                .keySpec(ImmutableList.of())
                .notificationSettings(EventNotificationSettings.withGracePeriod(60000))
                .priority(1)
                .build();
        final CorrelationCountProcessorParameters parameters = CorrelationCountProcessorParameters.builder()
                .timerange(timeRange)
                .build();
        AggregationSearch.Factory aggregationSearchFactory = null; // TODO find a way to have this

        CorrelationCountProcessor eventProcessor = new CorrelationCountProcessor(eventDefinitionDto, eventProcessorDependencyCheck,
                stateService, searches, moreSearch, messages, aggregationSearchFactory);
        assertThatCode(() -> eventProcessor.createEvents(eventFactory, parameters, (events) -> {
        }))
                .hasMessageContaining(eventDefinitionDto.title())
                .hasMessageContaining(eventDefinitionDto.id())
                .hasMessageContaining(timeRange.from().toString())
                .hasMessageContaining(timeRange.to().toString())
                .isInstanceOf(EventProcessorPreconditionException.class);
    }

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
                .groupingFields(new HashSet<>())
                .comment("test comment")
                .searchQuery("*")
                .build();

        CorrelationCount correlationCount = new CorrelationCount(searches, configuration, null, null);
        assertEquals(true, correlationCount.checkOrderSecondStream(summariesStream2, summariesStream1));
    }

    private CorrelationCountProcessorConfig getCorrelationCountProcessorConfig() {
        return CorrelationCountProcessorConfig.builder()
                .stream("main stream")
                .additionalStream("additional stream")
                .additionalThresholdType(ThresholdType.MORE.getDescription())
                .additionalThreshold(threshold)
                .thresholdType(ThresholdType.MORE.getDescription())
                .threshold(threshold)
                .messagesOrder("any order")
                .searchWithinMs(2 * 60 * 1000)
                .executeEveryMs(2 * 60 * 1000)
                .groupingFields(new HashSet<>())
                .comment("test comment")
                .searchQuery("*")
                .build();
    }
}
