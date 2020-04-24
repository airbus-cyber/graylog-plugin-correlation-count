package com.airbus_cyber_security.graylog;

import com.airbus_cyber_security.graylog.config.CorrelationCountProcessorConfig;
import com.google.common.collect.ImmutableList;
import org.graylog.events.event.Event;
import org.graylog.events.event.EventDto;
import org.graylog.events.event.EventFactory;
import org.graylog.events.event.EventWithContext;
import org.graylog.events.notifications.EventNotificationSettings;
import org.graylog.events.processor.*;
import org.graylog2.indexer.results.CountResult;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CorrelationCountProcessorTest {
    private final int threshold = 100;
    private final String REMOTE_STREAM_ID = "REMOTESTREAMMOCKID";

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
/*
    @Before
    public void setUp() {
        eventFactory = mock(EventFactory.class);
        stateService = mock(DBEventProcessorStateService.class);
        eventProcessorDependencyCheck = mock(EventProcessorDependencyCheck.class);
        searches = mock(Searches.class);
    }*/

    @Test
    public void testEvents() throws EventProcessorException {
        final DateTime now = DateTime.now(DateTimeZone.UTC);
        final AbsoluteRange timeRange = AbsoluteRange.create(now.minusHours(1), now.plusHours(1));
        //when(eventProcessorDependencyCheck.hasMessagesIndexedUpTo(any(DateTime.class))).thenReturn(true);
        // We expect to get the end of the aggregation timerange as event time
      /*  final EventDto eventDto = EventDto.builder()
                .eventDefinitionId("event_definition_id")
                .eventDefinitionType("event_definition_type")
                .eventTimestamp(now)
                .alert(true)
                .fields(new HashMap<>())
                .id("id")
                .key("")
                .keyTuple(new ArrayList<>())
                .message("message")
                .originContext("origin_context")
                .priority(1)
                .processingTimestamp(now)
                .source("source")
                .sourceStreams(new HashSet<>())
                .streams(new HashSet<>())
                .timerangeEnd(timeRange.to())
                .timerangeStart(timeRange.from())
                .build();
        final Event eventTest = Event.fromDto(eventDto);
        //final Event event2 = new Event(timeRange.to());
        when(eventFactory.createEvent(any(EventDefinition.class), eq(timeRange.to()), anyString()))
                .thenReturn(eventTest);  // first invocation return value
                //.thenReturn(event2); // second invocation return value
*/
        final EventDefinitionDto eventDefinitionDto = EventDefinitionDto.builder()
                .id("dto-id")
                .title("Test Correlation")
                .description("A test correlation event processors")
                .config(CorrelationCountProcessorConfig.builder()
                    .title("Test correlation config")
                    .additionalStream("additional stream")
                    .additionalThresholdType(CorrelationCountUtils.ThresholdType.MORE.getDescription())
                    .additionalThreshold(threshold)
                    .mainThresholdType(CorrelationCountUtils.ThresholdType.MORE.getDescription())
                    .mainThreshold(threshold)
                    .timeRange(2)
                    .messagesOrder("any order")
                    .gracePeriod(2)
                    .messageBacklog(1)
                    .groupingFields(new HashSet<>())
                    .searchQuery("*")
                    .build()
                )
                .alert(false)
                .keySpec(ImmutableList.of())
                .notificationSettings(EventNotificationSettings.withGracePeriod(60000))
                .priority(1)
                .build();
        final CorrelationCountProcessorParameters parameters = CorrelationCountProcessorParameters.builder()
                .timerange(timeRange)
                .build();

        CorrelationCountProcessor eventProcessor = new CorrelationCountProcessor(eventDefinitionDto, eventProcessorDependencyCheck, stateService, searches);
        //EventConsumer<List<EventWithContext>> eventConsumer = mock(EventConsumer.class);
        //when(eventProcessorDependencyCheck.hasMessagesIndexedUpTo(parameters.timerange().getTo())).thenReturn(true);
        //CountResult countResult = CountResult.create(1L, 500);
        //when(searches.count(anyString(), any(AbsoluteRange.class), anyString())).thenReturn(countResult);
        //when(eventFactory.createEvent(any(EventDefinition.class), any(DateTime.class), anyString())).thenReturn(eventTest);
        //eventProcessor.createEvents(eventFactory, parameters, eventConsumer);

        //eventProcessor.createEvents(eventFactory, parameters, EventConsumer<List< EventWithContext >> eventConsumer);
        assertThatCode(() -> eventProcessor.createEvents(eventFactory, parameters, (events) -> {}))
                .hasMessageContaining(eventDefinitionDto.title())
                .hasMessageContaining(eventDefinitionDto.id())
                .hasMessageContaining(timeRange.from().toString())
                .hasMessageContaining(timeRange.to().toString())
                .isInstanceOf(EventProcessorPreconditionException.class);
    }
}
