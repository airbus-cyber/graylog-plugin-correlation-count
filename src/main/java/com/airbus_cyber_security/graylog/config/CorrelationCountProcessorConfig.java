package com.airbus_cyber_security.graylog.config;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;
import org.graylog.events.contentpack.entities.EventProcessorConfigEntity;
import org.graylog.events.processor.EventProcessorConfig;
import org.graylog2.contentpacks.EntityDescriptorIds;
import org.graylog2.contentpacks.model.entities.references.ValueReference;
import org.graylog2.plugin.rest.ValidationResult;

import java.util.Set;

@AutoValue
@JsonTypeName(CorrelationCountProcessorConfig.TYPE_NAME)
@JsonDeserialize(builder = CorrelationCountProcessorConfig.Builder.class)
public abstract class CorrelationCountProcessorConfig implements EventProcessorConfig {
    public static final String TYPE_NAME = "correlation-count";

    private static final String FIELD_TITLE = "title";
    private static final String FIELD_ADDITIONAL_STREAM = "additional_stream";
    private static final String FIELD_ADDITIONAL_THRESHOLD_TYPE = "additional_threshold_type";
    private static final String FIELD_ADDITIONAL_THRESHOLD = "additional_threshold";
    private static final String FIELD_MAIN_THRESHOLD_TYPE = "main_threshold_type";
    private static final String FIELD_MAIN_THRESHOLD = "main_threshold";
    private static final String FIELD_TIME_RANGE = "time_range";
    private static final String FIELD_MESSAGES_ORDER = "messages_order";
    private static final String FIELD_GRACE_PERIOD = "grace_period";
    private static final String FIELD_MESSAGE_BACKLOG = "message_backlog";
    private static final String FIELD_GROUPING_FIELDS = "grouping_fields";
    private static final String FIELD_SEARCH_QUERY = "search_query";

    @JsonProperty(FIELD_TITLE)
    public abstract String title();

    @JsonProperty(FIELD_ADDITIONAL_STREAM)
    public abstract String additionalStream();

    @JsonProperty(FIELD_ADDITIONAL_THRESHOLD_TYPE)
    public abstract String additionalThresholdType();

    @JsonProperty(FIELD_ADDITIONAL_THRESHOLD)
    public abstract int additionalThreshold();

    @JsonProperty(FIELD_MAIN_THRESHOLD_TYPE)
    public abstract String mainThresholdType();

    @JsonProperty(FIELD_MAIN_THRESHOLD)
    public abstract int mainThreshold();

    @JsonProperty(FIELD_TIME_RANGE)
    public abstract int timeRange();

    @JsonProperty(FIELD_MESSAGES_ORDER)
    public abstract String messagesOrder();

    @JsonProperty(FIELD_GRACE_PERIOD)
    public abstract int gracePeriod();

    @JsonProperty(FIELD_MESSAGE_BACKLOG)
    public abstract int messageBacklog();

    @JsonProperty(FIELD_GROUPING_FIELDS)
    public abstract Set<String> groupingFields();

    @JsonProperty(FIELD_SEARCH_QUERY)
    public abstract String searchQuery();

    public static Builder builder() {
        return Builder.create();
    }

    public abstract Builder toBuilder();

    @AutoValue.Builder
    public static abstract class Builder implements EventProcessorConfig.Builder<Builder> {
        @JsonCreator
        public static Builder create() {
            return new AutoValue_CorrelationCountProcessorConfig.Builder()
                    .type(TYPE_NAME);
        }

        @JsonProperty(FIELD_TITLE)
        public abstract Builder title(String title);

        @JsonProperty(FIELD_ADDITIONAL_STREAM)
        public abstract Builder additionalStream(String additionalStream);

        @JsonProperty(FIELD_ADDITIONAL_THRESHOLD_TYPE)
        public abstract Builder additionalThresholdType(String additionalThresholdType);

        @JsonProperty(FIELD_ADDITIONAL_THRESHOLD)
        public abstract Builder additionalThreshold(int additionalThreshold);

        @JsonProperty(FIELD_MAIN_THRESHOLD_TYPE)
        public abstract Builder mainThresholdType(String mainThresholdType);

        @JsonProperty(FIELD_MAIN_THRESHOLD)
        public abstract Builder mainThreshold(int mainThreshold);

        @JsonProperty(FIELD_TIME_RANGE)
        public abstract Builder timeRange(int timeRange);

        @JsonProperty(FIELD_MESSAGES_ORDER)
        public abstract Builder messagesOrder(String messagesOrder);

        @JsonProperty(FIELD_GRACE_PERIOD)
        public abstract Builder gracePeriod(int gracePeriod);

        @JsonProperty(FIELD_MESSAGE_BACKLOG)
        public abstract Builder messageBacklog(int messageBacklog);

        @JsonProperty(FIELD_GROUPING_FIELDS)
        public abstract Builder groupingFields(Set<String> groupingFields);

        @JsonProperty(FIELD_SEARCH_QUERY)
        public abstract Builder searchQuery(String searchQuery);

        public abstract CorrelationCountProcessorConfig build();
    }

    @Override
    public ValidationResult validate() {
        ValidationResult validationResult = new ValidationResult();
        if(title() == null || title().isEmpty()) {
            validationResult.addError(FIELD_TITLE, "Title is mandatory");
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
        if(mainThresholdType() == null || mainThresholdType().isEmpty()) {
            validationResult.addError(FIELD_MAIN_THRESHOLD_TYPE, "Main threshold type is mandatory");
        }
        if(mainThreshold() < 0) {
            validationResult.addError(FIELD_MAIN_THRESHOLD, "Main threshold must be greater than 0.");
        }
        if(timeRange() < 0) {
            validationResult.addError(FIELD_TIME_RANGE, "Time range must be greater than 0.");
        }
        if(messagesOrder() == null || messagesOrder().isEmpty()) {
            validationResult.addError(FIELD_MESSAGES_ORDER, "Messages order is mandatory");
        }
        if(gracePeriod() < 0) {
            validationResult.addError(FIELD_GRACE_PERIOD, "Grace period must be greater than 0.");
        }
        if(messageBacklog() < 0) {
            validationResult.addError(FIELD_MESSAGE_BACKLOG, "Message backog must be greater than 0.");
        }
        return validationResult;
    }

    @Override
    public EventProcessorConfigEntity toContentPackEntity(EntityDescriptorIds entityDescriptorIds) {
        return CorrelationCountProcessorConfigEntity.builder()
                .title(ValueReference.of(title()))
                .additionalStream(ValueReference.of(additionalStream()))
                .additionalThresholdType(ValueReference.of(additionalThresholdType()))
                .additionalThreshold(additionalThreshold())
                .mainThresholdType(ValueReference.of(mainThresholdType()))
                .mainThreshold(mainThreshold())
                .timeRange(timeRange())
                .messagesOrder(ValueReference.of(messagesOrder()))
                .gracePeriod(gracePeriod())
                .messageBacklog(messageBacklog())
                .groupingFields(groupingFields())
                .searchQuery(ValueReference.of(searchQuery()))
                .build();
    }
}
