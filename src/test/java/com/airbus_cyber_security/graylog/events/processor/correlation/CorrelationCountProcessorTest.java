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

package com.airbus_cyber_security.graylog.events.processor.correlation;

import com.airbus_cyber_security.graylog.events.processor.correlation.checks.ThresholdType;
import com.google.common.collect.ImmutableList;
import org.graylog.events.event.EventFactory;
import org.graylog.events.notifications.EventNotificationSettings;
import org.graylog.events.processor.DBEventProcessorStateService;
import org.graylog.events.processor.EventDefinitionDto;
import org.graylog.events.processor.EventProcessorDependencyCheck;
import org.graylog.events.processor.EventProcessorPreconditionException;
import org.graylog.events.processor.aggregation.AggregationSearch;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.util.HashSet;

import static org.assertj.core.api.Assertions.assertThatCode;

public class CorrelationCountProcessorTest {

    @Rule
    public final MockitoRule mockitoRule = MockitoJUnit.rule();

    @Mock
    private EventFactory eventFactory;
    @Mock
    private DBEventProcessorStateService stateService;
    @Mock
    private EventProcessorDependencyCheck eventProcessorDependencyCheck;
    @Mock
    private Searches searches;

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
                stateService, searches, aggregationSearchFactory);
        assertThatCode(() -> eventProcessor.createEvents(eventFactory, parameters, (events) -> {
        }))
                .hasMessageContaining(eventDefinitionDto.title())
                .hasMessageContaining(eventDefinitionDto.id())
                .hasMessageContaining(timeRange.from().toString())
                .hasMessageContaining(timeRange.to().toString())
                .isInstanceOf(EventProcessorPreconditionException.class);
    }

    private CorrelationCountProcessorConfig getCorrelationCountProcessorConfig() {
        int threshold = 100;
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
