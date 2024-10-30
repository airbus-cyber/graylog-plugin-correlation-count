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

package com.airbus_cyber_security.graylog.events.contentpack.entities;

import com.airbus_cyber_security.graylog.events.processor.correlation.CorrelationCountProcessorConfig;
import com.airbus_cyber_security.graylog.events.processor.correlation.checks.OrderType;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;
import org.graylog.events.contentpack.entities.EventProcessorConfigEntity;
import org.graylog.events.processor.EventProcessorConfig;
import org.graylog2.contentpacks.model.entities.EntityDescriptor;
import org.graylog2.contentpacks.model.entities.references.ValueReference;

import java.util.List;
import java.util.Map;

@AutoValue
@JsonTypeName(CorrelationCountProcessorConfigEntity.TYPE_NAME)
@JsonDeserialize(builder = CorrelationCountProcessorConfigEntity.Builder.class)
public abstract class CorrelationCountProcessorConfigEntity implements EventProcessorConfigEntity {

    public static final String TYPE_NAME = "correlation-count";

    private static final String FIELD_STREAM = "stream";
    private static final String FIELD_ADDITIONAL_STREAM = "additional_stream";
    private static final String FIELD_ADDITIONAL_THRESHOLD_TYPE = "additional_threshold_type";
    private static final String FIELD_ADDITIONAL_THRESHOLD = "additional_threshold";
    private static final String FIELD_THRESHOLD_TYPE = "threshold_type";
    private static final String FIELD_THRESHOLD = "threshold";
    private static final String FIELD_MESSAGES_ORDER = "messages_order";
    private static final String FIELD_SEARCH_WITHIN_MS = "search_within_ms";
    private static final String FIELD_EXECUTE_EVERY_MS = "execute_every_ms";
    private static final String FIELD_GROUPING_FIELDS = "grouping_fields";
    private static final String FIELD_COMMENT = "comment";
    private static final String FIELD_SEARCH_QUERY = "search_query";
    private static final String FIELD_ADDITIONAL_SEARCH_QUERY = "additional_search_query";

    @JsonProperty(FIELD_STREAM)
    public abstract ValueReference stream();

    @JsonProperty(FIELD_ADDITIONAL_STREAM)
    public abstract ValueReference additionalStream();

    @JsonProperty(FIELD_ADDITIONAL_THRESHOLD_TYPE)
    public abstract ValueReference additionalThresholdType();

    @JsonProperty(FIELD_ADDITIONAL_THRESHOLD)
    public abstract int additionalThreshold();

    @JsonProperty(FIELD_THRESHOLD_TYPE)
    public abstract ValueReference thresholdType();

    @JsonProperty(FIELD_THRESHOLD)
    public abstract int threshold();

    @JsonProperty(FIELD_MESSAGES_ORDER)
    public abstract ValueReference messagesOrder();

    @JsonProperty(FIELD_SEARCH_WITHIN_MS)
    public abstract long searchWithinMs();

    @JsonProperty(FIELD_EXECUTE_EVERY_MS)
    public abstract long executeEveryMs();

    @JsonProperty(FIELD_GROUPING_FIELDS)
    public abstract List<String> groupingFields();

    @JsonProperty(FIELD_COMMENT)
    public abstract ValueReference comment();

    @JsonProperty(FIELD_SEARCH_QUERY)
    public abstract ValueReference searchQuery();

    @JsonProperty(value = FIELD_ADDITIONAL_SEARCH_QUERY)
    public abstract ValueReference additionalSearchQuery();

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

        @JsonProperty(FIELD_STREAM)
        public abstract Builder stream(ValueReference stream);

        @JsonProperty(FIELD_ADDITIONAL_STREAM)
        public abstract Builder additionalStream(ValueReference additionalStream);

        @JsonProperty(FIELD_ADDITIONAL_THRESHOLD_TYPE)
        public abstract Builder additionalThresholdType(ValueReference additionalThresholdType);

        @JsonProperty(FIELD_ADDITIONAL_THRESHOLD)
        public abstract Builder additionalThreshold(int additionalThreshold);

        @JsonProperty(FIELD_THRESHOLD_TYPE)
        public abstract Builder thresholdType(ValueReference thresholdType);

        @JsonProperty(FIELD_THRESHOLD)
        public abstract Builder threshold(int threshold);

        @JsonProperty(FIELD_MESSAGES_ORDER)
        public abstract Builder messagesOrder(ValueReference messagesOrder);

        @JsonProperty(FIELD_SEARCH_WITHIN_MS)
        public abstract Builder searchWithinMs(long searchWithinMs);

        @JsonProperty(FIELD_EXECUTE_EVERY_MS)
        public abstract Builder executeEveryMs(long executeEveryMs);

        @JsonProperty(FIELD_GROUPING_FIELDS)
        public abstract Builder groupingFields(List<String> groupingFields);

        @JsonProperty(FIELD_COMMENT)
        public abstract Builder comment(ValueReference comment);

        @JsonProperty(FIELD_SEARCH_QUERY)
        public abstract Builder searchQuery(ValueReference searchQuery);

        @JsonProperty(value = FIELD_ADDITIONAL_SEARCH_QUERY)
        public abstract Builder additionalSearchQuery(ValueReference additionalSearchQuery);

        public abstract CorrelationCountProcessorConfigEntity build();
    }

    @Override
    public EventProcessorConfig toNativeEntity(Map<String, ValueReference> parameters, Map<EntityDescriptor, Object> nativeEntities) {
        return CorrelationCountProcessorConfig.builder()
                .stream(stream().asString(parameters))
                .additionalStream(additionalStream().asString(parameters))
                .additionalThresholdType(additionalThresholdType().asString(parameters))
                .additionalThreshold(additionalThreshold())
                .thresholdType(thresholdType().asString(parameters))
                .threshold(threshold())
                .messagesOrder(OrderType.fromString(messagesOrder().asString(parameters)))
                .searchWithinMs(searchWithinMs())
                .executeEveryMs(executeEveryMs())
                .groupingFields(groupingFields())
                .comment(comment().asString(parameters))
                .searchQuery(searchQuery().asString(parameters))
                .additionalSearchQuery(additionalSearchQuery().asString(parameters))
                .build();
    }
}
