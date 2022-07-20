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
import com.google.common.primitives.Ints;
import com.google.inject.assistedinject.Assisted;
import org.graylog.events.event.Event;
import org.graylog.events.event.EventFactory;
import org.graylog.events.event.EventOriginContext;
import org.graylog.events.event.EventWithContext;
import org.graylog.events.processor.*;
import org.graylog.events.processor.aggregation.AggregationSearch;
import org.graylog.events.search.MoreSearch;
import org.graylog.plugins.views.search.Parameter;
import org.graylog2.indexer.results.ResultMessage;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
import org.graylog2.rest.models.search.responses.TermsResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

public class CorrelationCountProcessor implements EventProcessor {
    public interface Factory extends EventProcessor.Factory<CorrelationCountProcessor> {
        @Override
        CorrelationCountProcessor create(EventDefinition eventDefinition);
    }

    private static final Logger LOG = LoggerFactory.getLogger(CorrelationCountProcessor.class);

    private final EventDefinition eventDefinition;
    private final EventProcessorDependencyCheck dependencyCheck;
    private final DBEventProcessorStateService stateService;
    private final CorrelationCount correlationCount;
    private final CorrelationCountProcessorConfig configuration;
    private final MoreSearch moreSearch;

    @Inject
    public CorrelationCountProcessor(@Assisted EventDefinition eventDefinition, EventProcessorDependencyCheck dependencyCheck,
                                     DBEventProcessorStateService stateService, Searches searches, MoreSearch moreSearch, AggregationSearch.Factory aggregationSearchFactory) {
        this.eventDefinition = eventDefinition;
        this.dependencyCheck = dependencyCheck;
        this.stateService = stateService;
        this.configuration = (CorrelationCountProcessorConfig) eventDefinition.config();
        this.correlationCount = new CorrelationCount(searches, this.configuration, aggregationSearchFactory, eventDefinition);
        this.moreSearch = moreSearch;
    }

    @Override
    public void createEvents(EventFactory eventFactory, EventProcessorParameters eventProcessorParameters, EventConsumer<List<EventWithContext>> eventConsumer) throws EventProcessorException {
        TimeRange timerange = getTimeRangeFromParameters(eventProcessorParameters);

        // TODO: We have to take the Elasticsearch index.refresh_interval into account here!
        if (!dependencyCheck.hasMessagesIndexedUpTo(timerange.getTo())) {
            String msg = String.format(Locale.ROOT, "Couldn't run correlation count <%s/%s> for timerange <%s to %s> because required messages haven't been indexed, yet.",
                    this.eventDefinition.title(), this.eventDefinition.id(), timerange.getFrom(), timerange.getTo());
            throw new EventProcessorPreconditionException(msg, this.eventDefinition);
        }

        List<CorrelationCountResult> results = this.correlationCount.runCheck(timerange);
        List<EventWithContext> events = eventsFromCorrelationResults(eventFactory, timerange, results);
        eventConsumer.accept(events);
        // Update the state for this processor! This state will be used for dependency checks between event processors.
        this.stateService.setState(this.eventDefinition.id(), timerange.getFrom(), timerange.getTo());
    }

    ImmutableList<EventWithContext> eventsFromCorrelationResults(EventFactory eventFactory, TimeRange timerange, List<CorrelationCountResult> results) {
        ImmutableList.Builder<EventWithContext> listEvents = ImmutableList.builder();

        for (CorrelationCountResult result: results) {
            List<String> groupByFields = result.getGroupByFields();

            Map<String, Object> fields = new HashMap<>();
            List<String> fieldNames = new ArrayList<>(configuration.groupingFields());
            for (int i = 0; i < this.configuration.groupingFields().size(); i++) {
                String name = fieldNames.get(i);
                String value = groupByFields.get(i);
                fields.put(name, value);
            }

            String resultDescription = getResultDescription(result.getFirstStreamCount(), result.getSecondStreamCount());
            Message message = new Message(resultDescription, "", result.getTimestamp());
            message.addFields(fields);

            Event event = eventFactory.createEvent(this.eventDefinition, timerange.getFrom(), resultDescription);
            event.addSourceStream(this.configuration.stream());
            event.addSourceStream(this.configuration.additionalStream());

            event.setTimerangeStart(timerange.getFrom());
            event.setTimerangeEnd(timerange.getTo());

            EventWithContext eventWithContext = EventWithContext.create(event, message);
            listEvents.add(eventWithContext);
        }
        return listEvents.build();
    }

    private String getResultDescription(long countMainStream, long countAdditionalStream) {
        String msgCondition;
        if (OrderType.fromString(this.configuration.messagesOrder()).equals(OrderType.ANY)) {
            msgCondition = "and";
        } else {
            msgCondition = this.configuration.messagesOrder();
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
    public void sourceMessagesForEvent(Event event, Consumer<List<MessageSummary>> messageConsumer, long limit) throws EventProcessorException {
        // TODO try to imitate code of the AggregationCountProcessor (even, call it if possible)
        // should not have to redo all the computations performed in createEvent but rather use the information stored on the Event (again the grouping fields and timestamp)
        if (limit <= 0) {
            return;
        }
        TimeRange timeRange = AbsoluteRange.create(event.getTimerangeStart(), event.getTimerangeEnd());
        LOG.debug("[DEV] sourceMessagesForEvent: groupingFields={}", Arrays.deepToString(this.configuration.groupingFields().toArray())); // TODO remove this log line
        if (this.configuration.groupingFields().isEmpty()) {
            AtomicLong msgCount = new AtomicLong(0L);
            MoreSearch.ScrollCallback callback = (messages, continueScrolling) -> {
                List<MessageSummary> summaries = Lists.newArrayList();
                for (ResultMessage resultMessage : messages) {
                    if (msgCount.incrementAndGet() > limit) {
                        continueScrolling.set(false);
                        break;
                    }
                    Message msg = resultMessage.getMessage();
                    summaries.add(new MessageSummary(resultMessage.getIndex(), msg));
                }
                messageConsumer.accept(summaries);
            };
            Set<String> streams = new HashSet<>();
            streams.add(this.configuration.stream());
            streams.add(this.configuration.additionalStream());
            Set<Parameter> parameters = new HashSet<>();
            this.moreSearch.scrollQuery(this.configuration.searchQuery(), streams, parameters, timeRange, Math.min(500, Ints.saturatedCast(limit)), callback);

        } else {
            Collection<CorrelationCountResult> matchedTerms = this.correlationCount.getMatchedTerms(timeRange, limit);

            List<MessageSummary> summaries = Lists.newArrayList();
            Thresholds thresholds = new Thresholds(this.configuration);
            for (CorrelationCountResult matchedResult: matchedTerms) {
                if (!thresholds.areReached(matchedResult.getFirstStreamCount(), matchedResult.getSecondStreamCount())) {
                    continue;
                }
                List<String> groupByFields = matchedResult.getGroupByFields();
                //[CorrelationCount] [DEV] buildSearchQuery: matchedTerms=message:bob* AND source: 127.0.0.7
                //[CorrelationCount] [DEV] buildSearchQuery: matchedTerms=message:bob* AND source: 127.0.0.1
                String searchQuery = this.correlationCount.buildSearchQuery(groupByFields);
                List<MessageSummary> summariesMainStream = this.correlationCount.search(searchQuery, this.configuration.stream(), timeRange);
                List<MessageSummary> summariesAdditionalStream = this.correlationCount.search(searchQuery, this.configuration.additionalStream(), timeRange);
                summaries.addAll(summariesMainStream);
                summaries.addAll(summariesAdditionalStream);
            }
            messageConsumer.accept(summaries);
        }
    }
}
