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

import com.airbus_cyber_security.graylog.events.processor.correlation.checks.*;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.inject.assistedinject.Assisted;
import org.graylog.events.event.Event;
import org.graylog.events.event.EventFactory;
import org.graylog.events.event.EventWithContext;
import org.graylog.events.processor.*;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.*;
import java.util.function.Consumer;

// sources of inspiration:
// * org.graylog.events.processor.aggregation.AggregationEventProcessor
public class CorrelationCountProcessor implements EventProcessor {
    public interface Factory extends EventProcessor.Factory<CorrelationCountProcessor> {
        @Override
        CorrelationCountProcessor create(EventDefinition eventDefinition);
    }

    private static final Logger LOG = LoggerFactory.getLogger(CorrelationCountProcessor.class);

    private final EventDefinition eventDefinition;
    private final EventProcessorDependencyCheck dependencyCheck;
    private final DBEventProcessorStateService stateService;
    private final CorrelationCountProcessorConfig configuration;
    private final CorrelationCountCheck correlationCountCheck;
    private final CorrelationCountSearches correlationCountSearches;

    @Inject
    public CorrelationCountProcessor(@Assisted EventDefinition eventDefinition, EventProcessorDependencyCheck dependencyCheck,
                                     DBEventProcessorStateService stateService, CorrelationCountSearches correlationCountSearches) {
        this.eventDefinition = eventDefinition;
        this.dependencyCheck = dependencyCheck;
        this.stateService = stateService;
        this.configuration = (CorrelationCountProcessorConfig) eventDefinition.config();
        this.correlationCountCheck = new CorrelationCountCheck(this.configuration);
        this.correlationCountSearches = correlationCountSearches;
    }

    @Override
    public void createEvents(EventFactory eventFactory, EventProcessorParameters eventProcessorParameters, EventConsumer<List<EventWithContext>> eventConsumer) throws EventProcessorException {
        TimeRange timerange = getTimeRangeFromParameters(eventProcessorParameters);

        // TODO: We have to take the Elasticsearch index.refresh_interval into account here!
        if (!dependencyCheck.hasMessagesIndexedUpTo(timerange)) {
            String msg = String.format(Locale.ROOT, "Couldn't run correlation count <%s/%s> for timerange <%s to %s> because required messages haven't been indexed, yet.",
                    this.eventDefinition.title(), this.eventDefinition.id(), timerange.getFrom(), timerange.getTo());
            throw new EventProcessorPreconditionException(msg, this.eventDefinition);
        }

        List<CorrelationCountResult> results = runCheck(timerange);
        List<EventWithContext> events = eventsFromCorrelationResults(eventFactory, timerange, results);
        eventConsumer.accept(events);
        // Update the state for this processor! This state will be used for dependency checks between event processors.
        this.stateService.setState(this.eventDefinition.id(), timerange.getFrom(), timerange.getTo());
    }

    private ImmutableList<EventWithContext> eventsFromCorrelationResults(EventFactory eventFactory, TimeRange timerange, List<CorrelationCountResult> results) throws EventProcessorException {
        ImmutableList.Builder<EventWithContext> listEvents = ImmutableList.builder();

        for (CorrelationCountResult result: results) {
            Map<String, String> groupByFields = associateGroupByFields(result.getGroupByFields());

            String resultDescription = getResultDescription(result.getFirstStreamCount(), result.getSecondStreamCount());
            Message message = new Message(resultDescription, "", result.getTimestamp());
            for (Map.Entry<String, String> groupBy: groupByFields.entrySet()) {
                message.addField(groupBy.getKey(), groupBy.getValue());
            }

            // see https://github.com/Graylog2/graylog2-server/blob/5.0.0/graylog2-server/src/main/java/org/graylog/events/processor/aggregation/AggregationEventProcessor.java#L281
            Event event = eventFactory.createEvent(this.eventDefinition, result.getTimestamp(), resultDescription);
            event.addSourceStream(this.configuration.stream());
            event.addSourceStream(this.configuration.additionalStream());

            event.setTimerangeStart(this.calculateTimerangeStartFromTimestamp(result.getTimestamp()));
            event.setTimerangeEnd(result.getTimestamp());
            event.setGroupByFields(groupByFields);

            EventWithContext eventWithContext = EventWithContext.create(event, message);
            listEvents.add(eventWithContext);
        }
        return listEvents.build();
    }

    private String getResultDescription(long countMainStream, long countAdditionalStream) {
        String msgCondition;
        if (this.configuration.messagesOrder().equals(OrderType.ANY)) {
            msgCondition = "and";
        } else {
            msgCondition = this.configuration.messagesOrder().getDescription();
        }

        String resultDescription = "The additional stream had " + countAdditionalStream + " messages with trigger condition "
                + this.configuration.additionalThresholdType().toLowerCase(Locale.ENGLISH) + " than " + this.configuration.additionalThreshold()
                + " messages " + msgCondition + " the main stream had " + countMainStream + " messages with trigger condition "
                + this.configuration.thresholdType().toLowerCase(Locale.ENGLISH) + " than " + this.configuration.threshold() + " messages in the last " + this.configuration.searchWithinMs() + " milliseconds";

        if (!this.configuration.groupingFields().isEmpty()) {
            resultDescription = resultDescription + " with the same value of the fields " + String.join(", ", this.configuration.groupingFields());
        }

        return resultDescription + ". (Executes every: " + this.configuration.executeEveryMs() + " milliseconds)";
    }

    private TimeRange getTimeRangeFromParameters(EventProcessorParameters eventProcessorParameters) {
        CorrelationCountProcessorParameters parameters = (CorrelationCountProcessorParameters) eventProcessorParameters;
        return parameters.timerange();
    }

    @Override
    public void sourceMessagesForEvent(Event event, Consumer<List<MessageSummary>> messageConsumer, long limit) {
        if (limit <= 0) {
            return;
        }
        TimeRange timeRange = AbsoluteRange.create(event.getTimerangeStart(), event.getTimerangeEnd());
        Map<String, String> groupByFields = event.getGroupByFields();
        String searchQuery = this.configuration.searchQuery();
        List<MessageSummary> summariesMainStream = this.correlationCountSearches.searchMessages(searchQuery, groupByFields, this.configuration.stream(), timeRange);
        List<MessageSummary> summariesAdditionalStream = this.correlationCountSearches.searchMessages(searchQuery, groupByFields, this.configuration.additionalStream(), timeRange);
        List<MessageSummary> summaries = Lists.newArrayList();
        summaries.addAll(summariesMainStream);
        summaries.addAll(summariesAdditionalStream);
        messageConsumer.accept(summaries);
    }

    private Map<String, String> associateGroupByFields(List<String> groupByFields) throws EventProcessorException {
        Map<String, String> fields = new HashMap<>();
        List<String> fieldNames = this.configuration.groupingFields();
        for (int i = 0; i < fieldNames.size(); i++) {
            String name = fieldNames.get(i);
            try {
                String value = groupByFields.get(i);
                fields.put(name, value);
            } catch (IndexOutOfBoundsException e) {
                LOG.error("Expected {} groupBy fields in search result, but got {}", configuration.groupingFields().size(), groupByFields);
                throw new EventProcessorException("Couldn't create events for: " + eventDefinition.title(), true, eventDefinition.id(), eventDefinition, e);
            }
        }
        return fields;
    }

    private ImmutableList<CorrelationCountResult> runCheck(TimeRange timeRange) throws EventProcessorException {
        Collection<CorrelationCountResult> matchedResults = this.correlationCountSearches.count(timeRange, this.configuration, this.eventDefinition);

        ImmutableList.Builder<CorrelationCountResult> results = ImmutableList.builder();
        for (CorrelationCountResult matchedResult: matchedResults) {
            long firstStreamCount = matchedResult.getFirstStreamCount();
            long secondStreamCount = matchedResult.getSecondStreamCount();
            if (!this.correlationCountCheck.thresholdsAreReached(firstStreamCount, secondStreamCount)) {
                continue;
            }
            Map<String, String> groupByFields = associateGroupByFields(matchedResult.getGroupByFields());
            TimeRange searchTimeRange = buildSearchTimeRange(matchedResult.getTimestamp());

            String searchQuery = this.configuration.searchQuery();
            List<MessageSummary> summariesMainStream = this.correlationCountSearches.searchMessages(searchQuery, groupByFields, this.configuration.stream(), searchTimeRange);
            List<MessageSummary> summariesAdditionalStream = this.correlationCountSearches.searchMessages(searchQuery, groupByFields, this.configuration.additionalStream(), searchTimeRange);

            if (!this.correlationCountCheck.isRuleTriggered(summariesMainStream, summariesAdditionalStream)) {
                continue;
            }

            results.add(matchedResult);
        }
        return results.build();
    }

    private DateTime calculateTimerangeStartFromTimestamp(DateTime to) {
        // see https://github.com/Graylog2/graylog2-server/blob/5.0.0/graylog2-server/src/main/java/org/graylog/events/processor/aggregation/AggregationEventProcessor.java#L284
        return to.minus(this.configuration.searchWithinMs());
    }

    private TimeRange buildSearchTimeRange(DateTime to) {
        DateTime from = this.calculateTimerangeStartFromTimestamp(to);
        return AbsoluteRange.create(from, to);
    }
}
