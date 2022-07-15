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

package com.airbus_cyber_security.graylog.events.processor.correlation.checks;

import com.airbus_cyber_security.graylog.events.processor.correlation.CorrelationCountProcessorConfig;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import org.graylog.events.processor.EventDefinition;
import org.graylog.events.processor.EventProcessorException;
import org.graylog.events.processor.aggregation.*;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class CorrelationCountSearch {

    private final CorrelationCountProcessorConfig configuration;
    private final AggregationSearch.Factory aggregationSearchFactory;
    private final EventDefinition eventDefinition;
    // TODO: should distinguish by timestamps too!!
    private final Map<String, CorrelationCountResult> results;

    public CorrelationCountSearch(CorrelationCountProcessorConfig configuration, AggregationSearch.Factory aggregationSearchFactory, EventDefinition eventDefinition) {
        this.configuration = configuration;
        this.aggregationSearchFactory = aggregationSearchFactory;
        this.eventDefinition = eventDefinition;
        this.results = new HashMap<>();
    }
    private String buildTermKey(ImmutableList<String> groupByFields) {
        StringBuilder builder = new StringBuilder();
        for (String field: groupByFields) {
            if (0 < builder.length()) {
                builder.append(" - ");
            }
            builder.append(field);
        }
        return builder.toString();
    }

    private void setResult(String key, ImmutableList<String> groupByFields, long firstStreamCount, long secondStreamCount) {
        CorrelationCountResult result = new CorrelationCountResult(groupByFields, firstStreamCount, secondStreamCount);
        this.results.put(key, result);
    }

    // TODO add timestamp, change type of groupByFields to ImmutableList<String>
    private void addFirstStreamCount(ImmutableList<String> groupByFields, long firstStreamCount) {
        String key = buildTermKey(groupByFields);
        long secondStreamCount = 0L;
        this.setResult(key, groupByFields, firstStreamCount, secondStreamCount);
    }

    // TODO add timestamp, change type of groupByFields to ImmutableList<String>
    private void addSecondStreamCount(ImmutableList<String> groupByFields, long secondStreamCount) {
        String key = buildTermKey(groupByFields);
        long firstStreamCount = 0L;
        CorrelationCountResult previousResult = this.results.get(key);
        if (previousResult != null) {
            firstStreamCount = previousResult.getFirstStreamCount();
        }
        this.setResult(key, groupByFields, firstStreamCount, secondStreamCount);
    }

    private AggregationResult getTerms(String stream, TimeRange timeRange, long limit) throws EventProcessorException {
        // Build series from configuration
        ImmutableList.Builder<AggregationSeries> seriesBuilder = ImmutableList.builder();
        StringBuilder idBuilder = new StringBuilder("correlation_id");
        for (String groupingField : this.configuration.groupingFields()) {
            idBuilder.append("#").append(groupingField);
        }
        seriesBuilder.add(AggregationSeries.builder().id(idBuilder.toString()).function(AggregationFunction.COUNT).build());
        // Create the graylog "legal" aggregation configuration
        AggregationEventProcessorConfig config = AggregationEventProcessorConfig.Builder.create()
                .groupBy(new ArrayList<>(this.configuration.groupingFields()))
                .query(this.configuration.searchQuery())
                .streams(ImmutableSet.of(stream))
                .executeEveryMs(this.configuration.executeEveryMs())
                .searchWithinMs(this.configuration.searchWithinMs())
//                .conditions() // TODO or not TODO, that is the question
                .series(seriesBuilder.build())
                .build(); // TODO
        AggregationEventProcessorParameters parameters = AggregationEventProcessorParameters.builder()
                .streams(ImmutableSet.of(stream)).batchSize(Long.valueOf(limit).intValue())
                .timerange(timeRange)
                .build(); // TODO Check if this is correct
        String owner = "event-processor-" + AggregationEventProcessorConfig.TYPE_NAME + "-" + this.eventDefinition.id();
        AggregationSearch search = this.aggregationSearchFactory.create(config, parameters, owner, this.eventDefinition);
        return search.doSearch();
    }

    private long extractCount(AggregationKeyResult keyResult) {
        ImmutableList<AggregationSeriesValue> seriesValues = keyResult.seriesValues();
        // there should only be one series (the AggregationFunction.COUNT)
        AggregationSeriesValue seriesValue = seriesValues.get(0);
        return Double.valueOf(seriesValue.value()).longValue();
    }

    public Collection<CorrelationCountResult> doSearch(TimeRange timeRange, long limit) throws EventProcessorException {

        // Get matching terms in main stream
        AggregationResult termResult = getTerms(this.configuration.stream(), timeRange, limit);
        // Get matching terms in additional stream
        AggregationResult termResultAdditionalStream = getTerms(this.configuration.additionalStream(), timeRange, limit);

        for (AggregationKeyResult keyResult: termResult.keyResults()) {
            long value = extractCount(keyResult);

            addFirstStreamCount(keyResult.key(), value);
        }

        for (AggregationKeyResult keyResult: termResultAdditionalStream.keyResults()) {
            long value = extractCount(keyResult);

            addSecondStreamCount(keyResult.key(), value);
        }

        return this.results.values();
    }
}
