/*
 * graylog-plugin-correlation-count Source Code
 * Copyright (C) 2018-2020 - Airbus CyberSecurity (SAS) - All rights reserved
 *
 * This file is part of the graylog-plugin-correlation-count GPL Source Code.
 *
 * graylog-plugin-correlation-count Source Code is free software:
 * you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this code.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.airbus_cyber_security.graylog.events.processor.correlation.checks;

import com.airbus_cyber_security.graylog.events.processor.correlation.CorrelationCountProcessorConfig;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.Lists;
import org.graylog.events.search.MoreSearch;
import org.graylog2.indexer.results.CountResult;
import org.graylog2.indexer.results.ResultMessage;
import org.graylog2.indexer.results.SearchResult;
import org.graylog2.indexer.results.TermsResult;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.indexer.searches.Sorting;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
import org.joda.time.DateTime;

import java.util.*;

public class CorrelationCount {
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
    private final MoreSearch moreSearch;

    public CorrelationCount(MoreSearch moreSearch, CorrelationCountProcessorConfig configuration) {
        this.moreSearch = moreSearch;
        this.configuration = configuration;
        this.thresholds = new Thresholds(configuration);
    }

    public static List<MessageSummary> search(MoreSearch moreSearch, String searchQuery, String filter, TimeRange range) {
        SearchResult backlogResult = moreSearch.search(searchQuery, filter,
                range, SEARCH_LIMIT, 0, new Sorting(Message.FIELD_TIMESTAMP, Sorting.Direction.DESC));
        List<MessageSummary> result = Lists.newArrayList();
        for (ResultMessage resultMessage: backlogResult.getResults()) {
            result.add(new MessageSummary(resultMessage.getIndex(), resultMessage.getMessage()));
        }
        return result;
    }

    public static String buildSearchQuery(String firstField, List<String> nextFields, String matchedFieldValue, String searchQuery) {
        for (String field : nextFields) {
            matchedFieldValue = matchedFieldValue.replaceFirst(" - ", " AND " + field + ": ");
        }
        return (searchQuery + " AND " + firstField + ": " + matchedFieldValue);
    }

    private static List<DateTime> getListOrderTimestamp(List<MessageSummary> summaries, CorrelationCount.OrderType messagesOrderType){
        List<DateTime> listDate = new ArrayList<>();
        for (MessageSummary messageSummary : summaries) {
            listDate.add(messageSummary.getTimestamp());
        }
        Collections.sort(listDate);
        if(messagesOrderType.equals(CorrelationCount.OrderType.AFTER)) {
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
                        (messagesOrder.equals(CorrelationCount.OrderType.AFTER) && dateSecondStream.isAfter(dateFirstStream))){
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

    private static String getResultDescription(long countMainStream, long countAdditionalStream, CorrelationCountProcessorConfig config) {

        String msgCondition;
        if (CorrelationCount.OrderType.fromString(config.messagesOrder()).equals(CorrelationCount.OrderType.ANY)) {
            msgCondition = "and";
        } else {
            msgCondition = config.messagesOrder();
        }

        String resultDescription = "The additional stream had " + countAdditionalStream + " messages with trigger condition "
                + config.additionalThresholdType().toLowerCase(Locale.ENGLISH) + " than " + config.additionalThreshold()
                + " messages " + msgCondition + " the main stream had " + countMainStream + " messages with trigger condition "
                + config.thresholdType().toLowerCase(Locale.ENGLISH) + " than " + config.threshold() + " messages in the last " + config.searchWithinMs() + " milliseconds";

        if (!config.groupingFields().isEmpty()) {
            resultDescription = resultDescription + " with the same value of the fields " + String.join(", ",config.groupingFields());
        }

        return resultDescription + ". (Executes every: " + config.executeEveryMs() + " milliseconds)";
    }

    private boolean isRuleTriggered(List<MessageSummary> summariesMainStream, List<MessageSummary> summariesAdditionalStream) {
        if (CorrelationCount.OrderType.fromString(this.configuration.messagesOrder()).equals(CorrelationCount.OrderType.ANY)) {
            return true;
        }
        return checkOrderSecondStream(summariesMainStream, summariesAdditionalStream);
    }

    public static Map<String, Long[]> getMatchedTerms(TermsResult termResult, TermsResult termResultAdditionalStrem){

        Map<String, Long[]> matchedTerms = new HashMap<>();
        for (Map.Entry<String, Long> term: termResult.getTerms().entrySet()) {
            Long termAdditionalStreamValue = termResultAdditionalStrem.getTerms().getOrDefault(term.getKey(), 0L);
            matchedTerms.put(term.getKey(), new Long[] {term.getValue(), termAdditionalStreamValue});
        }
        for (Map.Entry<String, Long> termAdditionalStream: termResultAdditionalStrem.getTerms().entrySet()) {
            if(!matchedTerms.containsKey(termAdditionalStream.getKey())){
                matchedTerms.put(termAdditionalStream.getKey(), new Long[] {0L, termAdditionalStream.getValue()});
            }
        }

        return matchedTerms;
    }

    public CorrelationCountCheckResult runCheckCorrelationCount(TimeRange timerange, MoreSearch moreSearch, CorrelationCountProcessorConfig config) {
        String filterMainStream = HEADER_STREAM + config.stream();
        CountResult resultMainStream = moreSearch.count(config.searchQuery(), timerange, filterMainStream);
        String filterAdditionalStream = HEADER_STREAM + config.additionalStream();
        CountResult resultAdditionalStream = moreSearch.count(config.searchQuery(), timerange, filterAdditionalStream);

        if (!this.thresholds.areReached(resultMainStream.count(), resultAdditionalStream.count())) {
            return new CorrelationCountCheckResult("", new ArrayList<>());
        }

        List<MessageSummary> summariesMainStream = search(moreSearch, config.searchQuery(), filterMainStream, timerange);
        List<MessageSummary> summariesAdditionalStream = search(moreSearch, config.searchQuery(), filterAdditionalStream, timerange);

        if (!isRuleTriggered(summariesMainStream, summariesAdditionalStream)) {
            return new CorrelationCountCheckResult("", new ArrayList<>());
        }

        List<MessageSummary> summaries = Lists.newArrayList();
        summaries.addAll(summariesMainStream);
        summaries.addAll(summariesAdditionalStream);
        String resultDescription = getResultDescription(resultMainStream.count(), resultAdditionalStream.count(), config);
        return new CorrelationCountCheckResult(resultDescription, summaries);
    }

    public CorrelationCountCheckResult runCheckCorrelationWithFields(TimeRange timerange, MoreSearch moreSearch, CorrelationCountProcessorConfig config) {
        String filterMainStream = HEADER_STREAM + config.stream();
        String filterAdditionalStream = HEADER_STREAM + config.additionalStream();
        boolean ruleTriggered = false;

        List<String> nextFields = new ArrayList<>(config.groupingFields());
        String firstField = config.groupingFields().iterator().next();
        nextFields.remove(0);

        TermsResult termResult = moreSearch.terms(firstField, nextFields, SEARCH_LIMIT, config.searchQuery(), filterMainStream, timerange, Sorting.Direction.DESC);
        TermsResult termResultAdditionalStream = moreSearch.terms(firstField, nextFields, SEARCH_LIMIT, config.searchQuery(), filterAdditionalStream, timerange, Sorting.Direction.DESC);
        Map<String, Long[]> matchedTerms = getMatchedTerms(termResult, termResultAdditionalStream);

        long countFirstMainStream = 0;
        long countFirstAdditionalStream = 0;
        boolean isFirstTriggered = true;
        final List<MessageSummary> summaries = Lists.newArrayList();
        for (Map.Entry<String, Long[]> matchedTerm: matchedTerms.entrySet()) {
            String matchedFieldValue = matchedTerm.getKey();
            Long[] counts = matchedTerm.getValue();

            if (this.thresholds.areReached(counts[0], counts[1])) {
                String searchQuery = buildSearchQuery(firstField, nextFields, matchedFieldValue, config.searchQuery());
                List<MessageSummary> summariesMainStream = search(moreSearch, searchQuery, filterMainStream, timerange);
                List<MessageSummary> summariesAdditionalStream = search(moreSearch, searchQuery, filterAdditionalStream, timerange);

                if (isRuleTriggered(summariesMainStream, summariesAdditionalStream)) {
                    ruleTriggered = true;
                    if(isFirstTriggered) {
                        countFirstMainStream = counts[0];
                        countFirstAdditionalStream = counts[1];
                        isFirstTriggered = false;
                    }
                    summaries.addAll(summariesMainStream);
                    summaries.addAll(summariesAdditionalStream);
                }
            }
        }

        if (ruleTriggered) {
            String resultDescription = getResultDescription(countFirstMainStream, countFirstAdditionalStream, config);
            return new CorrelationCountCheckResult(resultDescription, summaries);
        }
        return new CorrelationCountCheckResult("", new ArrayList<>());
    }

    public CorrelationCountCheckResult runCheck(TimeRange timerange) {
        if (this.configuration.groupingFields().isEmpty()) {
            return runCheckCorrelationCount(timerange, this.moreSearch, this.configuration);
        } else {
            return runCheckCorrelationWithFields(timerange, this.moreSearch, this.configuration);
        }
    }
}
