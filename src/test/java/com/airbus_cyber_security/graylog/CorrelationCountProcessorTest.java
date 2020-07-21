package com.airbus_cyber_security.graylog;

import com.airbus_cyber_security.graylog.events.processor.correlation.CorrelationCountProcessorConfig;
import com.google.common.collect.ImmutableList;
import org.graylog.events.event.EventFactory;
import org.graylog.events.notifications.EventNotificationSettings;
import org.graylog.events.processor.*;
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

import java.util.*;

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

        CorrelationCountProcessor eventProcessor = new CorrelationCountProcessor(eventDefinitionDto, eventProcessorDependencyCheck,
                stateService, searches, messages);
        assertThatCode(() -> eventProcessor.createEvents(eventFactory, parameters, (events) -> {}))
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

        CorrelationCountProcessorConfig config = CorrelationCountProcessorConfig.builder()
                .stream("main stream")
                .additionalStream("additional stream")
                .additionalThresholdType(CorrelationCountUtils.ThresholdType.MORE.getDescription())
                .additionalThreshold(1)
                .thresholdType(CorrelationCountUtils.ThresholdType.MORE.getDescription())
                .threshold(4)
                .timeRange(10)
                .messagesOrder("additional messages after main messages")
                .gracePeriod(0)
                .messageBacklog(1)
                .groupingFields(new HashSet<>())
                .comment("test comment")
                .searchQuery("*")
                .repeatNotifications(false)
                .build();

        assertEquals(true, CorrelationCountUtils.checkOrderSecondStream(summariesStream2, summariesStream1, config));
    }

    private CorrelationCountProcessorConfig getCorrelationCountProcessorConfig() {
        return CorrelationCountProcessorConfig.builder()
                .stream("main stream")
                .additionalStream("additional stream")
                .additionalThresholdType(CorrelationCountUtils.ThresholdType.MORE.getDescription())
                .additionalThreshold(threshold)
                .thresholdType(CorrelationCountUtils.ThresholdType.MORE.getDescription())
                .threshold(threshold)
                .timeRange(2)
                .messagesOrder("any order")
                .gracePeriod(2)
                .messageBacklog(1)
                .groupingFields(new HashSet<>())
                .comment("test comment")
                .searchQuery("*")
                .repeatNotifications(false)
                .build();
    }
}
