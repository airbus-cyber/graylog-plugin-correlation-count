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
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import org.graylog.events.processor.EventDefinition;
import org.graylog.events.processor.EventProcessorException;
import org.graylog.events.processor.aggregation.*;
import org.graylog2.indexer.results.CountResult;
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

    enum OrderType {

        ANY("ANY"),
        BEFORE("BEFORE"),
        AFTER("AFTER");

        private final String description;

        OrderType(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }

        public static OrderType fromString(String text) {
            for (OrderType orderType : OrderType.values()) {
                if (orderType.description.equals(text)) {
                    return orderType;
                }
            }
            throw new IllegalArgumentException("Unknown OrderType value: " + text);
        }
    }

    private final CorrelationCountProcessorConfig configuration;
    private final Thresholds thresholds;
    private final Searches searches;
    private final CorrelationCountSearch correlationCountSearch;

    public CorrelationCount(Searches searches, CorrelationCountProcessorConfig configuration, AggregationSearch.Factory aggregationSearchFactory, EventDefinition eventDefinition) {
        this.correlationCountSearch = new CorrelationCountSearch(configuration, aggregationSearchFactory, eventDefinition);
        this.searches = searches;
        this.configuration = configuration;
        this.thresholds = new Thresholds(configuration);
    }

    public List<MessageSummary> search(String searchQuery, String stream, TimeRange range) {
        String filter = HEADER_STREAM + stream;
        SearchResult backlogResult = this.searches.search(searchQuery, filter,
                range, SEARCH_LIMIT, 0, new Sorting(Message.FIELD_TIMESTAMP, Sorting.Direction.DESC));
        List<MessageSummary> result = Lists.newArrayList();
        for (ResultMessage resultMessage: backlogResult.getResults()) {
            result.add(new MessageSummary(resultMessage.getIndex(), resultMessage.getMessage()));
        }
        return result;
    }

    public String buildSearchQuery(List<String> fieldValues) {
        List<String> fieldNames = new ArrayList<>(configuration.groupingFields());

        StringBuilder builder = new StringBuilder(this.configuration.searchQuery());
        for (int i = 0; i < fieldNames.size(); i++) {
            String name = fieldNames.get(i);
            String value = fieldValues.get(i);
            builder.append(" AND " + name + ": " + value);
        }
        return builder.toString();
    }

    private List<DateTime> getListOrderTimestamp(List<MessageSummary> summaries, CorrelationCount.OrderType messagesOrderType) {
        List<DateTime> listDate = new ArrayList<>();
        for (MessageSummary messageSummary : summaries) {
            listDate.add(messageSummary.getTimestamp());
        }
        Collections.sort(listDate);
        if (messagesOrderType.equals(CorrelationCount.OrderType.AFTER)) {
            Collections.reverse(listDate);
        }
        return listDate;
    }

    /*
     * Check that the Second Stream is before or after the first stream
     */
    @VisibleForTesting
    protected boolean checkOrderSecondStream(List<MessageSummary> summariesFirstStream, List<MessageSummary> summariesSecondStream) {
        int countFirstStream = summariesFirstStream.size();
        CorrelationCount.OrderType messagesOrder = CorrelationCount.OrderType.fromString(this.configuration.messagesOrder());
        List<DateTime> listDateFirstStream = getListOrderTimestamp(summariesFirstStream, messagesOrder);
        List<DateTime> listDateSecondStream = getListOrderTimestamp(summariesSecondStream, messagesOrder);

        for (DateTime dateFirstStream: listDateFirstStream) {
            int countSecondStream = 0;
            for (DateTime dateSecondStream: listDateSecondStream) {
                if ((messagesOrder.equals(CorrelationCount.OrderType.BEFORE) && dateSecondStream.isBefore(dateFirstStream)) ||
                        (messagesOrder.equals(CorrelationCount.OrderType.AFTER) && dateSecondStream.isAfter(dateFirstStream))) {
                    countSecondStream++;
                } else {
                    break;
                }
            }
            if (this.thresholds.areReached(countFirstStream, countSecondStream)) {
                return true;
            }
            countFirstStream--;
        }
        return false;
    }

    private String getResultDescription(long countMainStream, long countAdditionalStream) {
        String msgCondition;
        if (CorrelationCount.OrderType.fromString(this.configuration.messagesOrder()).equals(CorrelationCount.OrderType.ANY)) {
            msgCondition = "and";
        } else {
            msgCondition = this.configuration.messagesOrder();
        }

        String resultDescription = "The additional stream had " + countAdditionalStream + " messages with trigger condition "
                + this.configuration.additionalThresholdType().toLowerCase(Locale.ENGLISH) + " than " + this.configuration.additionalThreshold()
                + " messages " + msgCondition + " the main stream had " + countMainStream + " messages with trigger condition "
                + this.configuration.thresholdType().toLowerCase(Locale.ENGLISH) + " than " + this.configuration.threshold() + " messages in the last " + this.configuration.searchWithinMs() + " milliseconds";

        if (!this.configuration.groupingFields().isEmpty()) {
            resultDescription = resultDescription + " with the same value of the fields " + String.join(", ", this.configuration.groupingFields());
        }

        return resultDescription + ". (Executes every: " + this.configuration.executeEveryMs() + " milliseconds)";
    }

    private boolean isRuleTriggered(List<MessageSummary> summariesMainStream, List<MessageSummary> summariesAdditionalStream) {
        if (CorrelationCount.OrderType.fromString(this.configuration.messagesOrder()).equals(CorrelationCount.OrderType.ANY)) {
            return true;
        }
        return checkOrderSecondStream(summariesMainStream, summariesAdditionalStream);
    }

    // TODO try to remove this method
    public Collection<CorrelationCountResult> getMatchedTerms(TimeRange timeRange, long limit) throws EventProcessorException {
        return this.correlationCountSearch.doSearch(timeRange, limit);
    }

    private TimeRange buildSearchTimeRange(DateTime to) {
        DateTime from = to.minusSeconds((int) (this.configuration.searchWithinMs() / 1000));
        // TODO: will have to remove the minusMillis(1), once we migrate past Graylog 4.3.0 (see Graylog issue #11550)
        return AbsoluteRange.create(from, to.minusMillis(1));
    }

    // TODO should rather return a list of Events...
    public CorrelationCountCheckResult runCheck(TimeRange timeRange) throws EventProcessorException {
        Collection<CorrelationCountResult> matchedResults = getMatchedTerms(timeRange, SEARCH_LIMIT);

        ImmutableList.Builder<CorrelationCountResult> results = ImmutableList.builder();
        for (CorrelationCountResult matchedResult: matchedResults) {
            long firstStreamCount = matchedResult.getFirstStreamCount();
            long secondStreamCount = matchedResult.getSecondStreamCount();
            if (!this.thresholds.areReached(firstStreamCount, secondStreamCount)) {
                continue;
            }
            List<String> groupByFields = matchedResult.getGroupByFields();
            String searchQuery = buildSearchQuery(groupByFields);

            TimeRange searchTimeRange = buildSearchTimeRange(matchedResult.getTimestamp());

            List<MessageSummary> summariesMainStream = search(searchQuery, this.configuration.stream(), searchTimeRange);
            List<MessageSummary> summariesAdditionalStream = search(searchQuery, this.configuration.additionalStream(), searchTimeRange);

            if (!isRuleTriggered(summariesMainStream, summariesAdditionalStream)) {
                continue;
            }

            results.add(matchedResult);
        }
        ImmutableList<CorrelationCountResult> events = results.build();

        if (events.isEmpty()) {
            return new CorrelationCountCheckResult("", new ArrayList<>());
        }

        List<MessageSummary> summaries = Lists.newArrayList();
        CorrelationCountResult firstResult = events.get(0);
        List<String> groupByFields = firstResult.getGroupByFields();

        Map<String, Object> fields = new HashMap<>();
        List<String> fieldNames = new ArrayList<>(configuration.groupingFields());
        for (int i = 0; i < this.configuration.groupingFields().size(); i++) {
            String name = fieldNames.get(i);
            String value = groupByFields.get(i);
            fields.put(name, value);
        }

        String resultDescription = getResultDescription(firstResult.getFirstStreamCount(), firstResult.getSecondStreamCount());
        Message message = new Message(resultDescription, "", firstResult.getTimestamp());
        message.addFields(fields);
        summaries.add(new MessageSummary("Unused index", message));

        return new CorrelationCountCheckResult(resultDescription, summaries);
    }
}
