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
import com.google.common.collect.Lists;
import org.graylog.events.processor.EventDefinition;
import org.graylog.events.processor.EventProcessorException;
import org.graylog.events.processor.aggregation.AggregationEventProcessorConfig;
import org.graylog.events.processor.aggregation.AggregationEventProcessorParameters;
import org.graylog.events.processor.aggregation.AggregationKeyResult;
import org.graylog.events.processor.aggregation.AggregationResult;
import org.graylog.events.processor.aggregation.AggregationSearch;
import org.graylog.events.processor.aggregation.AggregationSeriesValue;
import org.graylog.events.search.MoreSearch;
import org.graylog.plugins.views.search.searchtypes.pivot.SeriesSpec;
import org.graylog.plugins.views.search.searchtypes.pivot.series.Count;
import org.graylog2.indexer.results.ResultMessage;
import org.graylog2.indexer.results.SearchResult;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.indexer.searches.Sorting;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
import org.joda.time.DateTime;

import jakarta.inject.Inject;
import org.joda.time.DateTimeZone;

import java.util.Collection;
import java.util.List;
import java.util.Map;

public class CorrelationCountSearches {

    private static final int SEARCH_LIMIT = 500;
    private static final String HEADER_STREAM = "streams:";
    private final AggregationSearch.Factory aggregationSearchFactory;
    // TODO should probably use MoreSearch rather than Searches (see code of AggregationEventProcessor)
    private final Searches searches;

    @Inject
    public CorrelationCountSearches(AggregationSearch.Factory aggregationSearchFactory, Searches searches) {
        this.aggregationSearchFactory = aggregationSearchFactory;
        this.searches = searches;
    }

    private AggregationResult getTerms(String stream, TimeRange timeRange, CorrelationCountProcessorConfig configuration, EventDefinition eventDefinition, String searchQuery) throws EventProcessorException {
        // Build series from configuration
        ImmutableList.Builder<SeriesSpec> seriesBuilder = ImmutableList.builder();
        StringBuilder idBuilder = new StringBuilder("correlation_id");
        for (String groupingField: configuration.groupingFields()) {
            idBuilder.append("#").append(groupingField);
        }
        Count countSeries = Count.builder().id(idBuilder.toString()).build();
        seriesBuilder.add(countSeries);
        // Create the graylog "legal" aggregation configuration
        AggregationEventProcessorConfig config = AggregationEventProcessorConfig.builder()
                .groupBy(configuration.groupingFields())
                .query(searchQuery)
                .streams(ImmutableSet.of(stream))
                .executeEveryMs(configuration.executeEveryMs())
                .searchWithinMs(configuration.searchWithinMs())
                .series(seriesBuilder.build())
                .build();
        AggregationEventProcessorParameters parameters = AggregationEventProcessorParameters.builder()
                .streams(ImmutableSet.of(stream)).batchSize(Long.valueOf(SEARCH_LIMIT).intValue())
                .timerange(timeRange)
                .build();
        String owner = "event-processor-" + AggregationEventProcessorConfig.TYPE_NAME + "-" + eventDefinition.id();
        AggregationSearch search = this.aggregationSearchFactory.create(config, parameters, new AggregationSearch.User(owner, DateTimeZone.UTC), eventDefinition, List.of());
        return search.doSearch();
    }

    private long extractCount(AggregationKeyResult keyResult) {
        ImmutableList<AggregationSeriesValue> seriesValues = keyResult.seriesValues();
        // there should only be one series (the AggregationFunction.COUNT)
        AggregationSeriesValue seriesValue = seriesValues.get(0);
        return Double.valueOf(seriesValue.value()).longValue();
    }

    public Collection<CorrelationCountResult> count(TimeRange timeRange, CorrelationCountProcessorConfig configuration, EventDefinition eventDefinition) throws EventProcessorException {

        AggregationResult termResult = getTerms(configuration.stream(), timeRange, configuration, eventDefinition, configuration.searchQuery());
        AggregationResult termResultAdditionalStream = getTerms(configuration.additionalStream(), timeRange, configuration, eventDefinition, configuration.additionalSearchQuery());

        CorrelationCountCombinedResults results = new CorrelationCountCombinedResults();

        for (AggregationKeyResult keyResult: termResult.keyResults()) {
            ImmutableList<String> groupByFields = keyResult.key();
            DateTime timestamp = keyResult.timestamp().get();
            long value = extractCount(keyResult);

            results.addFirstStreamResult(timestamp, groupByFields, value);
        }

        for (AggregationKeyResult keyResult: termResultAdditionalStream.keyResults()) {
            ImmutableList<String> groupByFields = keyResult.key();
            DateTime timestamp = keyResult.timestamp().get();
            long value = extractCount(keyResult);

            results.addSecondStreamResult(timestamp, groupByFields, value);
        }

        return results.getAll();
    }

    private String buildSearchQuery(String searchQuery, Map<String, String> groupByFields) {
        // TODO: should searchQuery be sanitized?
        StringBuilder builder = new StringBuilder(searchQuery);
        for (Map.Entry<String, String> groupBy: groupByFields.entrySet()) {
            String name = groupBy.getKey();
            String value = MoreSearch.luceneEscape(groupBy.getValue());
            builder.append(" AND ").append(name).append(": \"").append(value).append("\"");
        }
        return builder.toString();
    }

    public List<MessageSummary> searchMessages(String additionalQuery, Map<String, String> groupByFields, String stream, TimeRange range) {
        String searchQuery = this.buildSearchQuery(additionalQuery, groupByFields);
        String filter = HEADER_STREAM + stream;
        SearchResult backlogResult = this.searches.search(searchQuery, filter,
                range, SEARCH_LIMIT, 0, new Sorting(Message.FIELD_TIMESTAMP, Sorting.Direction.DESC));
        List<MessageSummary> result = Lists.newArrayList();
        for (ResultMessage resultMessage: backlogResult.getResults()) {
            result.add(new MessageSummary(resultMessage.getIndex(), resultMessage.getMessage()));
        }
        return result;
    }
}
