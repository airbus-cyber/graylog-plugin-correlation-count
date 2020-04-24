package com.airbus_cyber_security.graylog.config;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;
import org.graylog.events.contentpack.entities.EventProcessorConfigEntity;
import org.graylog.events.processor.EventProcessorConfig;
import org.graylog2.contentpacks.model.entities.EntityDescriptor;
import org.graylog2.contentpacks.model.entities.references.ValueReference;

import java.util.Map;
import java.util.Set;

@AutoValue
@JsonTypeName(CorrelationCountProcessorConfigEntity.TYPE_NAME)
@JsonDeserialize(builder = CorrelationCountProcessorConfigEntity.Builder.class)
public abstract class CorrelationCountProcessorConfigEntity implements EventProcessorConfigEntity {

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
    public abstract ValueReference title();

    @JsonProperty(FIELD_ADDITIONAL_STREAM)
    public abstract ValueReference additionalStream();

    @JsonProperty(FIELD_ADDITIONAL_THRESHOLD_TYPE)
    public abstract ValueReference additionalThresholdType();

    @JsonProperty(FIELD_ADDITIONAL_THRESHOLD)
    public abstract int additionalThreshold();

    @JsonProperty(FIELD_MAIN_THRESHOLD_TYPE)
    public abstract ValueReference mainThresholdType();

    @JsonProperty(FIELD_MAIN_THRESHOLD)
    public abstract int mainThreshold();

    @JsonProperty(FIELD_TIME_RANGE)
    public abstract int timeRange();

    @JsonProperty(FIELD_MESSAGES_ORDER)
    public abstract ValueReference messagesOrder();

    @JsonProperty(FIELD_GRACE_PERIOD)
    public abstract int gracePeriod();

    @JsonProperty(FIELD_MESSAGE_BACKLOG)
    public abstract int messageBacklog();

    @JsonProperty(FIELD_GROUPING_FIELDS)
    public abstract Set<String> groupingFields();

    @JsonProperty(FIELD_SEARCH_QUERY)
    public abstract ValueReference searchQuery();

    public static Builder builder() {
        return Builder.create();
    }

    public abstract Builder toBuilder();

    @AutoValue.Builder
    public static abstract class Builder implements EventProcessorConfigEntity.Builder<Builder> {
        @JsonCreator
        public static Builder create() {
            return new AutoValue_CorrelationCountProcessorConfigEntity.Builder()
                    .type(TYPE_NAME);
        }

        @JsonProperty(FIELD_TITLE)
        public abstract Builder title(ValueReference title);

        @JsonProperty(FIELD_ADDITIONAL_STREAM)
        public abstract Builder additionalStream(ValueReference additionalStream);

        @JsonProperty(FIELD_ADDITIONAL_THRESHOLD_TYPE)
        public abstract Builder additionalThresholdType(ValueReference additionalThresholdType);

        @JsonProperty(FIELD_ADDITIONAL_THRESHOLD)
        public abstract Builder additionalThreshold(int additionalThreshold);

        @JsonProperty(FIELD_MAIN_THRESHOLD_TYPE)
        public abstract Builder mainThresholdType(ValueReference mainThresholdType);

        @JsonProperty(FIELD_MAIN_THRESHOLD)
        public abstract Builder mainThreshold(int mainThreshold);

        @JsonProperty(FIELD_TIME_RANGE)
        public abstract Builder timeRange(int timeRange);

        @JsonProperty(FIELD_MESSAGES_ORDER)
        public abstract Builder messagesOrder(ValueReference messagesOrder);

        @JsonProperty(FIELD_GRACE_PERIOD)
        public abstract Builder gracePeriod(int gracePeriod);

        @JsonProperty(FIELD_MESSAGE_BACKLOG)
        public abstract Builder messageBacklog(int messageBacklog);

        @JsonProperty(FIELD_GROUPING_FIELDS)
        public abstract Builder groupingFields(Set<String> groupingFields);

        @JsonProperty(FIELD_SEARCH_QUERY)
        public abstract Builder searchQuery(ValueReference searchQuery);

        public abstract CorrelationCountProcessorConfigEntity build();
    }

    @Override
    public EventProcessorConfig toNativeEntity(Map<String, ValueReference> parameters, Map<EntityDescriptor, Object> nativeEntities) {
        return CorrelationCountProcessorConfig.builder()
                .title(title().asString(parameters))
                .additionalStream(additionalStream().asString(parameters))
                .additionalThresholdType(additionalThresholdType().asString(parameters))
                .additionalThreshold(additionalThreshold())
                .mainThresholdType(mainThresholdType().asString(parameters))
                .mainThreshold(mainThreshold())
                .timeRange(timeRange())
                .messagesOrder(messagesOrder().asString(parameters))
                .gracePeriod(gracePeriod())
                .messageBacklog(messageBacklog())
                .groupingFields(groupingFields())
                .searchQuery(searchQuery().asString(parameters))
                .build();
    }
}
