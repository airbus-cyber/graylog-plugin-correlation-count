package com.airbus_cyber_security.graylog.events.processor.correlation;

import com.airbus_cyber_security.graylog.events.processor.correlation.checks.CorrelationCount;
import com.airbus_cyber_security.graylog.events.processor.correlation.checks.CorrelationCountCheckResult;
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
import org.graylog.events.search.MoreSearch;
import org.graylog.plugins.views.search.Parameter;
import org.graylog2.indexer.messages.Messages;
import org.graylog2.indexer.results.ResultMessage;
import org.graylog2.indexer.results.TermsResult;
import org.graylog2.indexer.searches.Sorting;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
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
    private final Messages messages;
    private final CorrelationCount correlationCount;
    private final CorrelationCountProcessorConfig configuration;
    private final MoreSearch moreSearch;

    @Inject
    public CorrelationCountProcessor(@Assisted EventDefinition eventDefinition, EventProcessorDependencyCheck dependencyCheck,
                                     DBEventProcessorStateService stateService, MoreSearch moreSearch, Messages messages) {
        this.eventDefinition = eventDefinition;
        this.dependencyCheck = dependencyCheck;
        this.stateService = stateService;
        this.messages = messages;
        this.configuration = (CorrelationCountProcessorConfig) eventDefinition.config();
        this.correlationCount = new CorrelationCount(moreSearch, configuration);
        this.moreSearch = moreSearch;
    }

    @Override
    public void createEvents(EventFactory eventFactory, EventProcessorParameters eventProcessorParameters, EventConsumer<List<EventWithContext>> eventConsumer) throws EventProcessorException {
        final CorrelationCountProcessorParameters parameters = (CorrelationCountProcessorParameters) eventProcessorParameters;

        TimeRange timerange = parameters.timerange();
        // TODO: We have to take the Elasticsearch index.refresh_interval into account here!
        if (!dependencyCheck.hasMessagesIndexedUpTo(timerange.getTo())) {
            final String msg = String.format(Locale.ROOT, "Couldn't run correlation count <%s/%s> for timerange <%s to %s> because required messages haven't been indexed, yet.",
                    eventDefinition.title(), eventDefinition.id(), timerange.getFrom(), parameters.timerange().getTo());
            throw new EventProcessorPreconditionException(msg, eventDefinition);
        }

        CorrelationCountCheckResult correlationCountCheckResult = this.correlationCount.runCheck(timerange);
        final Event event = eventFactory.createEvent(eventDefinition, timerange.getFrom(), correlationCountCheckResult.getResultDescription());
        event.addSourceStream(configuration.stream());
        event.addSourceStream(configuration.additionalStream());

        event.setTimerangeStart(timerange.getFrom());
        event.setTimerangeEnd(timerange.getTo());

        if(correlationCountCheckResult.getMessageSummaries() != null && !correlationCountCheckResult.getMessageSummaries().isEmpty()) {
            MessageSummary msgSummary = correlationCountCheckResult.getMessageSummaries().get(0);
            event.setOriginContext(EventOriginContext.elasticsearchMessage(msgSummary.getIndex(), msgSummary.getId()));
            LOG.debug("Created event: [id: " + event.getId() + "], [message: " + event.getMessage() + "].");

            final ImmutableList.Builder<EventWithContext> listEvents = ImmutableList.builder();
            // TODO: Choose a better message for the context
            EventWithContext eventWithContext = EventWithContext.create(event, msgSummary.getRawMessage());
            listEvents.add(eventWithContext);
            eventConsumer.accept(listEvents.build());
        }
        // Update the state for this processor! This state will be used for dependency checks between event processors.
        stateService.setState(eventDefinition.id(), timerange.getFrom(), parameters.timerange().getTo());
    }

    @Override
    public void sourceMessagesForEvent(Event event, Consumer<List<MessageSummary>> messageConsumer, long limit) throws EventProcessorException {
        if (limit <= 0) {
            return;
        }
        final TimeRange timeRange = AbsoluteRange.create(event.getTimerangeStart(), event.getTimerangeEnd());
        if (this.configuration.groupingFields().isEmpty()) {
            final AtomicLong msgCount = new AtomicLong(0L);
            final MoreSearch.ScrollCallback callback = (messages, continueScrolling) -> {

                final List<MessageSummary> summaries = Lists.newArrayList();
                for (final ResultMessage resultMessage : messages) {
                    if (msgCount.incrementAndGet() > limit) {
                        continueScrolling.set(false);
                        break;
                    }
                    final Message msg = resultMessage.getMessage();
                    summaries.add(new MessageSummary(resultMessage.getIndex(), msg));
                }
                messageConsumer.accept(summaries);
            };
            Set<String> streams = new HashSet<>();
            streams.add(configuration.stream());
            streams.add(configuration.additionalStream());
            Set<Parameter> parameters = new HashSet<>();
            moreSearch.scrollQuery(configuration.searchQuery(), streams, parameters, timeRange, Math.min(500, Ints.saturatedCast(limit)), callback);

        } else {
            String filterMainStream = "streams:" + configuration.stream();
            String filterAdditionalStream = "streams:" + configuration.additionalStream();

            List<String> nextFields = new ArrayList<>(configuration.groupingFields());
            String firstField = configuration.groupingFields().iterator().next();
            nextFields.remove(0);

            TermsResult termResult = moreSearch.terms(firstField, nextFields, (int)limit, configuration.searchQuery(),
                    filterMainStream, timeRange, Sorting.Direction.DESC);
            TermsResult termResultAdditionalStream = moreSearch.terms(firstField, nextFields, (int)limit,
                    configuration.searchQuery(), filterAdditionalStream, timeRange, Sorting.Direction.DESC);
            Map<String, Long[]> matchedTerms = CorrelationCount.getMatchedTerms(termResult, termResultAdditionalStream);

            final List<MessageSummary> summaries = Lists.newArrayList();
            Thresholds thresholds = new Thresholds(configuration);
            for (Map.Entry<String, Long[]> matchedTerm: matchedTerms.entrySet()) {
                String matchedFieldValue = matchedTerm.getKey();
                Long[] counts = matchedTerm.getValue();
                if (thresholds.areReached(counts[0], counts[1])) {
                    String searchQuery = CorrelationCount.buildSearchQuery(firstField, nextFields, matchedFieldValue, configuration.searchQuery());
                    List<MessageSummary> summariesMainStream = CorrelationCount.search(moreSearch, searchQuery, filterMainStream, timeRange);
                    List<MessageSummary> summariesAdditionalStream = CorrelationCount.search(moreSearch, searchQuery, filterAdditionalStream, timeRange);
                     summaries.addAll(summariesMainStream);
                     summaries.addAll(summariesAdditionalStream);
                }
            }
            messageConsumer.accept(summaries);
        }


    }
}
