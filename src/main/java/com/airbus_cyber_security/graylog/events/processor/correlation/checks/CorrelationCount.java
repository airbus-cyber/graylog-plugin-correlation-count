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
import com.google.common.collect.Lists;
import org.graylog.events.processor.EventDefinition;
import org.graylog.events.processor.EventProcessorException;
import org.graylog.events.processor.aggregation.*;
import org.graylog2.indexer.results.ResultMessage;
import org.graylog2.indexer.results.SearchResult;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.indexer.searches.Sorting;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

// TODO could rename this class into CorrelationCountSearch
public class CorrelationCount {
    private static final Logger LOG = LoggerFactory.getLogger(CorrelationCount.class);
    private static final int SEARCH_LIMIT = 500;

    private static final String HEADER_STREAM = "streams:";

    private final CorrelationCountProcessorConfig configuration;
    private final CorrelationCountCheck correlationCountCheck;

    // TODO should probably use MoreSearch rather than Searches (see code of AggregationEventProcessor)
    private final Searches searches;
    private final CorrelationCountSearches correlationCountSearches;

    public CorrelationCount(Searches searches, CorrelationCountProcessorConfig configuration, AggregationSearch.Factory aggregationSearchFactory, EventDefinition eventDefinition) {
        this.correlationCountSearches = new CorrelationCountSearches(configuration, aggregationSearchFactory, eventDefinition);
        this.searches = searches;
        this.configuration = configuration;
        this.correlationCountCheck = new CorrelationCountCheck(configuration, configuration.messagesOrder());
    }

    public List<MessageSummary> searchMessages(String searchQuery, String stream, TimeRange range) {
        String filter = HEADER_STREAM + stream;
        SearchResult backlogResult = this.searches.search(searchQuery, filter,
                range, SEARCH_LIMIT, 0, new Sorting(Message.FIELD_TIMESTAMP, Sorting.Direction.DESC));
        List<MessageSummary> result = Lists.newArrayList();
        for (ResultMessage resultMessage: backlogResult.getResults()) {
            result.add(new MessageSummary(resultMessage.getIndex(), resultMessage.getMessage()));
        }
        return result;
    }

    public String buildSearchQuery(Map<String, String> groupByFields) {
        StringBuilder builder = new StringBuilder(this.configuration.searchQuery());
        for (Map.Entry<String, String> groupBy: groupByFields.entrySet()) {
            String name = groupBy.getKey();
            String value = groupBy.getValue();
            // TODO should escape the value here. Method org.graylog.events.search.MoreSearch.LuceneEscape probably works
            builder.append(" AND " + name + ": " + value);
        }
        return builder.toString();
    }

    public Map<String, String> associateGroupByFields(List<String> groupByFields) {
        Map<String, String> fields = new HashMap<>();
        List<String> fieldNames = new ArrayList<>(configuration.groupingFields());
        for (int i = 0; i < this.configuration.groupingFields().size(); i++) {
            String name = fieldNames.get(i);
            String value = groupByFields.get(i);
            fields.put(name, value);
        }
        return fields;
    }

    private TimeRange buildSearchTimeRange(DateTime to) {
        DateTime from = to.minusSeconds((int) (this.configuration.searchWithinMs() / 1000));
        // TODO: will have to remove the minusMillis(1), once we migrate past Graylog 4.3.0 (see Graylog issue #11550)
        return AbsoluteRange.create(from, to.minusMillis(1));
    }

    public ImmutableList<CorrelationCountResult> runCheck(TimeRange timeRange) throws EventProcessorException {
        Collection<CorrelationCountResult> matchedResults = this.correlationCountSearches.count(timeRange, SEARCH_LIMIT);

        ImmutableList.Builder<CorrelationCountResult> results = ImmutableList.builder();
        for (CorrelationCountResult matchedResult: matchedResults) {
            long firstStreamCount = matchedResult.getFirstStreamCount();
            long secondStreamCount = matchedResult.getSecondStreamCount();
            if (!this.correlationCountCheck.thresholdsAreReached(firstStreamCount, secondStreamCount)) {
                continue;
            }
            Map<String, String> groupByFields = associateGroupByFields(matchedResult.getGroupByFields());
            String searchQuery = buildSearchQuery(groupByFields);

            TimeRange searchTimeRange = buildSearchTimeRange(matchedResult.getTimestamp());

            List<MessageSummary> summariesMainStream = searchMessages(searchQuery, this.configuration.stream(), searchTimeRange);
            List<MessageSummary> summariesAdditionalStream = searchMessages(searchQuery, this.configuration.additionalStream(), searchTimeRange);

            if (!this.correlationCountCheck.isRuleTriggered(summariesMainStream, summariesAdditionalStream)) {
                continue;
            }

            results.add(matchedResult);
        }
        return results.build();
    }
}
