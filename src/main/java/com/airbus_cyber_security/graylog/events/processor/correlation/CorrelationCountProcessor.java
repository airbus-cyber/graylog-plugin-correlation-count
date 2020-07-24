package com.airbus_cyber_security.graylog.events.processor.correlation;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.Lists;
import com.google.inject.assistedinject.Assisted;
import org.graylog.events.event.Event;
import org.graylog.events.event.EventFactory;
import org.graylog.events.event.EventOriginContext;
import org.graylog.events.event.EventWithContext;
import org.graylog.events.processor.*;
import org.graylog.events.search.MoreSearch;
import org.graylog2.indexer.messages.Messages;
import org.graylog2.indexer.results.ResultMessage;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

public class CorrelationCountProcessor implements EventProcessor {
    public interface Factory extends EventProcessor.Factory<CorrelationCountProcessor> {
        @Override
        CorrelationCountProcessor create(EventDefinition eventDefinition);
    }

    private static final Logger LOG = LoggerFactory.getLogger(CorrelationCountProcessor.class);

    private final EventDefinition eventDefinition;
    private final CorrelationCountProcessorConfig config;
    private final EventProcessorDependencyCheck dependencyCheck;
    private final DBEventProcessorStateService stateService;
    private final Searches searches;
    private final Messages messages;

    @Inject
    public CorrelationCountProcessor(@Assisted EventDefinition eventDefinition, EventProcessorDependencyCheck dependencyCheck,
                                     DBEventProcessorStateService stateService, Searches searches, Messages messages) {
        this.eventDefinition = eventDefinition;
        this.config = (CorrelationCountProcessorConfig) eventDefinition.config();
        this.dependencyCheck = dependencyCheck;
        this.stateService = stateService;
        this.searches = searches;
        this.messages = messages;
    }

    @Override
    public void createEvents(EventFactory eventFactory, EventProcessorParameters eventProcessorParameters, EventConsumer<List<EventWithContext>> eventConsumer) throws EventProcessorException {
        final CorrelationCountProcessorParameters parameters = (CorrelationCountProcessorParameters) eventProcessorParameters;

        // TODO: We have to take the Elasticsearch index.refresh_interval into account here!
        if (!dependencyCheck.hasMessagesIndexedUpTo(parameters.timerange().getTo())) {
            final String msg = String.format(Locale.ROOT, "Couldn't run correlation count <%s/%s> for timerange <%s to %s> because required messages haven't been indexed, yet.",
                    eventDefinition.title(), eventDefinition.id(), parameters.timerange().getFrom(), parameters.timerange().getTo());
            throw new EventProcessorPreconditionException(msg, eventDefinition);
        }

        CorrelationCountCheckResult correlationCountCheckResult = getCorrelationCountCheckResult(searches, config);

        if (correlationCountCheckResult != null) {
            final Event event = eventFactory.createEvent(eventDefinition, parameters.timerange().getFrom(), correlationCountCheckResult.getResultDescription());
            LOG.debug("Created event: [id: " + event.getId() + "], [message: " + event.getMessage() + "].");
            List<EventWithContext> listEvents = new ArrayList<>();
            for (MessageSummary messageSummary : correlationCountCheckResult.getMessageSummaries()) {
                EventWithContext eventWithContext = EventWithContext.create(event, messageSummary.getRawMessage());
                LOG.debug("Created event: id ", eventWithContext.event().getId(), eventWithContext.event().getMessage());
                listEvents.add(eventWithContext);
            }
            eventConsumer.accept(listEvents);
        }


        // Update the state for this processor! This state will be used for dependency checks between event processors.
        stateService.setState(eventDefinition.id(), parameters.timerange().getFrom(), parameters.timerange().getTo());
    }

    @Override
    public void sourceMessagesForEvent(Event event, Consumer<List<MessageSummary>> messageConsumer, long limit) throws EventProcessorException {
        if (config.messageBacklog()>0) {//TODO condition should be the one triggered
            if (limit <= 0) {
                return;
            }
            final EventOriginContext.ESEventOriginContext esContext =
                    EventOriginContext.parseESContext(event.getOriginContext()).orElseThrow(
                            () -> new EventProcessorException("Failed to parse origin context", false, eventDefinition));
            try {
                final ResultMessage message;
                message = messages.get(esContext.messageId(), esContext.indexName());
                messageConsumer.accept(Lists.newArrayList(new MessageSummary(message.getIndex(), message.getMessage())));
            } catch (IOException e) {
                throw new EventProcessorException("Failed to query origin context message", false, eventDefinition, e);
            }

        } else {
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
        }
    }

    @VisibleForTesting
    CorrelationCountCheckResult getCorrelationCountCheckResult(Searches searches, CorrelationCountProcessorConfig config) {
        if(config.groupingFields().isEmpty()) {
            return CorrelationCount.runCheckCorrelationCount(searches, config);
        }
        else {
            return CorrelationCount.runCheckCorrelationWithFields(searches, config);
        }
    }
}
