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

import com.airbus_cyber_security.graylog.events.contentpack.entities.CorrelationCountProcessorConfigEntity;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;
import org.graylog.events.contentpack.entities.EventProcessorConfigEntity;
import org.graylog.events.processor.EventDefinition;
import org.graylog.events.processor.EventProcessorConfig;
import org.graylog.events.processor.EventProcessorExecutionJob;
import org.graylog.events.processor.EventProcessorSchedulerConfig;
import org.graylog.scheduler.clock.JobSchedulerClock;
import org.graylog.scheduler.schedule.IntervalJobSchedule;
import org.graylog2.contentpacks.EntityDescriptorIds;
import org.graylog2.contentpacks.model.entities.references.ValueReference;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.graylog2.plugin.rest.ValidationResult;
import org.joda.time.DateTime;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@AutoValue
@JsonTypeName(CorrelationCountProcessorConfig.TYPE_NAME)
@JsonDeserialize(builder = CorrelationCountProcessorConfig.Builder.class)
public abstract class CorrelationCountProcessorConfig implements EventProcessorConfig {
    public static final String TYPE_NAME = "correlation-count";

    private static final String FIELD_STREAM = "stream";
    private static final String FIELD_ADDITIONAL_STREAM = "additional_stream";
    private static final String FIELD_ADDITIONAL_THRESHOLD_TYPE = "additional_threshold_type";
    private static final String FIELD_ADDITIONAL_THRESHOLD = "additional_threshold";
    private static final String FIELD_THRESHOLD_TYPE = "threshold_type";
    private static final String FIELD_THRESHOLD = "threshold";
    private static final String FIELD_MESSAGES_ORDER = "messages_order";
    private static final String FIELD_GROUPING_FIELDS = "grouping_fields";
    private static final String FIELD_COMMENT = "comment";
    private static final String FIELD_SEARCH_QUERY = "search_query";
    private static final String FIELD_SEARCH_WITHIN_MS = "search_within_ms";
    private static final String FIELD_EXECUTE_EVERY_MS = "execute_every_ms";

    @JsonProperty(FIELD_STREAM)
    public abstract String stream();

    @JsonProperty(FIELD_ADDITIONAL_STREAM)
    public abstract String additionalStream();

    @JsonProperty(FIELD_ADDITIONAL_THRESHOLD_TYPE)
    public abstract String additionalThresholdType();

    @JsonProperty(FIELD_ADDITIONAL_THRESHOLD)
    public abstract int additionalThreshold();

    @JsonProperty(FIELD_THRESHOLD_TYPE)
    public abstract String thresholdType();

    @JsonProperty(FIELD_THRESHOLD)
    public abstract int threshold();

    @JsonProperty(FIELD_MESSAGES_ORDER)
    public abstract String messagesOrder();

    @JsonProperty(FIELD_SEARCH_WITHIN_MS)
    public abstract long searchWithinMs();

    @JsonProperty(FIELD_EXECUTE_EVERY_MS)
    public abstract long executeEveryMs();

    @JsonProperty(FIELD_GROUPING_FIELDS)
    public abstract List<String> groupingFields();

    @JsonProperty(FIELD_COMMENT)
    public abstract String comment();

    @JsonProperty(FIELD_SEARCH_QUERY)
    public abstract String searchQuery();

    public static Builder builder() {
        return Builder.create();
    }

    public abstract Builder toBuilder();

    @Override
    public Optional<EventProcessorSchedulerConfig> toJobSchedulerConfig(EventDefinition eventDefinition, JobSchedulerClock clock) {
        final DateTime now = clock.nowUTC();

        // We need an initial timerange for the first execution of the event processor
        final AbsoluteRange timerange = AbsoluteRange.create(now.minus(searchWithinMs()), now);

        final EventProcessorExecutionJob.Config jobDefinitionConfig = EventProcessorExecutionJob.Config.builder()
                .eventDefinitionId(eventDefinition.id())
                .processingWindowSize(searchWithinMs())
                .processingHopSize(executeEveryMs())
                .parameters(CorrelationCountProcessorParameters.builder()
                        .timerange(timerange)
                        .build())
                .build();
        final IntervalJobSchedule schedule = IntervalJobSchedule.builder()
                .interval(executeEveryMs())
                .unit(TimeUnit.MILLISECONDS)
                .build();

        return Optional.of(EventProcessorSchedulerConfig.create(jobDefinitionConfig, schedule));
    }

    @AutoValue.Builder
    public static abstract class Builder implements EventProcessorConfig.Builder<Builder> {
        @JsonCreator
        public static Builder create() {
            return new AutoValue_CorrelationCountProcessorConfig.Builder()
                    .type(TYPE_NAME);
        }

        @JsonProperty(FIELD_STREAM)
        public abstract Builder stream(String stream);

        @JsonProperty(FIELD_ADDITIONAL_STREAM)
        public abstract Builder additionalStream(String additionalStream);

        @JsonProperty(FIELD_ADDITIONAL_THRESHOLD_TYPE)
        public abstract Builder additionalThresholdType(String additionalThresholdType);

        @JsonProperty(FIELD_ADDITIONAL_THRESHOLD)
        public abstract Builder additionalThreshold(int additionalThreshold);

        @JsonProperty(FIELD_THRESHOLD_TYPE)
        public abstract Builder thresholdType(String thresholdType);

        @JsonProperty(FIELD_THRESHOLD)
        public abstract Builder threshold(int threshold);

        @JsonProperty(FIELD_MESSAGES_ORDER)
        public abstract Builder messagesOrder(String messagesOrder);

        @JsonProperty(FIELD_SEARCH_WITHIN_MS)
        public abstract Builder searchWithinMs(long searchWithinMs);

        @JsonProperty(FIELD_EXECUTE_EVERY_MS)
        public abstract Builder executeEveryMs(long executeEveryMs);

        @JsonProperty(FIELD_GROUPING_FIELDS)
        public abstract Builder groupingFields(List<String> groupingFields);

        @JsonProperty(FIELD_COMMENT)
        public abstract Builder comment(String comment);

        @JsonProperty(FIELD_SEARCH_QUERY)
        public abstract Builder searchQuery(String searchQuery);

        public abstract CorrelationCountProcessorConfig build();
    }

    @Override
    public ValidationResult validate() {
        ValidationResult validationResult = new ValidationResult();

        if (searchWithinMs() <= 0) {
            validationResult.addError(FIELD_SEARCH_WITHIN_MS,
                    "Correlation Count Alert Condition search_within_ms must be greater than 0.");
        }
        if (executeEveryMs() <= 0) {
            validationResult.addError(FIELD_EXECUTE_EVERY_MS,
                    "Filter & Aggregation execute_every_ms must be greater than 0.");
        }
        if(stream() == null || stream().isEmpty()) {
            validationResult.addError(FIELD_STREAM, "Stream is mandatory");
        }
        if(additionalStream() == null || additionalStream().isEmpty()) {
            validationResult.addError(FIELD_ADDITIONAL_STREAM, "Additional stream is mandatory");
        }
        if(additionalThresholdType() == null || additionalThresholdType().isEmpty()) {
            validationResult.addError(FIELD_ADDITIONAL_THRESHOLD_TYPE, "Additional threshold type is mandatory");
        }
        if (additionalThreshold() < 0) {
            validationResult.addError(FIELD_ADDITIONAL_THRESHOLD, "Additional threshold must be greater than 0.");
        }
        if(thresholdType() == null || thresholdType().isEmpty()) {
            validationResult.addError(FIELD_THRESHOLD_TYPE, "Threshold type is mandatory");
        }
        if(threshold() < 0) {
            validationResult.addError(FIELD_THRESHOLD, "Threshold must be greater than 0.");
        }
        if(messagesOrder() == null || messagesOrder().isEmpty()) {
            validationResult.addError(FIELD_MESSAGES_ORDER, "Messages order is mandatory");
        }
        return validationResult;
    }

    @Override
    public EventProcessorConfigEntity toContentPackEntity(EntityDescriptorIds entityDescriptorIds) {
        return CorrelationCountProcessorConfigEntity.builder()
                .stream(ValueReference.of(stream()))
                .additionalStream(ValueReference.of(additionalStream()))
                .additionalThresholdType(ValueReference.of(additionalThresholdType()))
                .additionalThreshold(additionalThreshold())
                .thresholdType(ValueReference.of(thresholdType()))
                .threshold(threshold())
                .messagesOrder(ValueReference.of(messagesOrder()))
                .searchWithinMs(searchWithinMs())
                .executeEveryMs(executeEveryMs())
                .groupingFields(groupingFields())
                .comment(ValueReference.of(comment()))
                .searchQuery(ValueReference.of(searchQuery()))
                .build();
    }
}
