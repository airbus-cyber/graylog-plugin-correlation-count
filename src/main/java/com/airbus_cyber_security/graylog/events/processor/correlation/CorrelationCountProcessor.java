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

import com.airbus_cyber_security.graylog.events.processor.correlation.checks.CorrelationCount;
import com.airbus_cyber_security.graylog.events.processor.correlation.checks.CorrelationCountCheckResult;
import com.airbus_cyber_security.graylog.events.processor.correlation.checks.CorrelationCountResult;
import com.airbus_cyber_security.graylog.events.processor.correlation.checks.Thresholds;
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

        CorrelationCountCheckResult correlationCountCheckResult = this.correlationCount.runCheck(timerange);
        Event event = eventFactory.createEvent(this.eventDefinition, timerange.getFrom(), correlationCountCheckResult.getResultDescription());
        event.addSourceStream(this.configuration.stream());
        event.addSourceStream(this.configuration.additionalStream());

        event.setTimerangeStart(timerange.getFrom());
        event.setTimerangeEnd(timerange.getTo());

        if (correlationCountCheckResult.getMessageSummaries() != null && !correlationCountCheckResult.getMessageSummaries().isEmpty()) {
            MessageSummary msgSummary = correlationCountCheckResult.getMessageSummaries().get(0);

            ImmutableList.Builder<EventWithContext> listEvents = ImmutableList.builder();
            // TODO: Choose a better message for the context
            EventWithContext eventWithContext = EventWithContext.create(event, msgSummary.getRawMessage());
            listEvents.add(eventWithContext);
            eventConsumer.accept(listEvents.build());
        }
        // Update the state for this processor! This state will be used for dependency checks between event processors.
        this.stateService.setState(this.eventDefinition.id(), timerange.getFrom(), timerange.getTo());
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
