package com.airbus_cyber_security.graylog;

import com.airbus_cyber_security.graylog.config.CorrelationCountProcessorConfig;
import com.google.inject.assistedinject.Assisted;
import org.graylog.events.event.Event;
import org.graylog.events.event.EventFactory;
import org.graylog.events.event.EventWithContext;
import org.graylog.events.processor.*;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.plugin.MessageSummary;

import javax.inject.Inject;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;

public class CorrelationCountProcessor implements EventProcessor {
    public interface Factory extends EventProcessor.Factory<CorrelationCountProcessor> {
        @Override
        CorrelationCountProcessor create(EventDefinition eventDefinition);
    }

    private final EventDefinition eventDefinition;
    private final CorrelationCountProcessorConfig config;
    private final EventProcessorDependencyCheck dependencyCheck;
    private final DBEventProcessorStateService stateService;
    private final Searches searches;

    @Inject
    public CorrelationCountProcessor(@Assisted EventDefinition eventDefinition, EventProcessorDependencyCheck dependencyCheck,
                                     DBEventProcessorStateService stateService, Searches searches) {
        this.eventDefinition = eventDefinition;
        this.config = (CorrelationCountProcessorConfig) eventDefinition.config();
        this.dependencyCheck = dependencyCheck;
        this.stateService = stateService;
        this.searches = searches;
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

        CorrelationCountCheckResult correlationCountCheckResult;
        if (config.groupingFields().isEmpty()){
            correlationCountCheckResult = CorrelationCountUtils.runCheckCorrelationCount(searches, config);
        }
        else {
            correlationCountCheckResult = CorrelationCountUtils.runCheckCorrelationWithFields(searches, config);
        }

        if (correlationCountCheckResult != null) {
            final Event event = eventFactory.createEvent(eventDefinition, parameters.timerange().getFrom(), correlationCountCheckResult.getResultDescription());
            List<EventWithContext> listEvents = new ArrayList<>();
            EventWithContext eventWithContext = EventWithContext.create(event);
            listEvents.add(eventWithContext);
            eventConsumer.accept(listEvents);
        }


        // Update the state for this processor! This state will be used for dependency checks between event processors.
        stateService.setState(eventDefinition.id(), parameters.timerange().getFrom(), parameters.timerange().getTo());
    }

    @Override
    public void sourceMessagesForEvent(Event event, Consumer<List<MessageSummary>> consumer, long limit) throws EventProcessorException {
        CorrelationCountCheckResult correlationCountCheckResult;
        if (config.groupingFields().isEmpty()){
            correlationCountCheckResult = CorrelationCountUtils.runCheckCorrelationCount(searches, config);
        }
        else {
            correlationCountCheckResult = CorrelationCountUtils.runCheckCorrelationWithFields(searches, config);
        }

        if (correlationCountCheckResult != null) {
            consumer.accept(correlationCountCheckResult.getMessageSummaries());
        }
    }
}
