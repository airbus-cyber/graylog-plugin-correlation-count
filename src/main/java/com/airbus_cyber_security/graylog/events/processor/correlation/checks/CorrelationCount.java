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
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
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
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
import org.graylog2.rest.models.search.responses.TermsResult;
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
    private final AggregationSearch.Factory aggregationSearchFactory;
    private final EventDefinition eventDefinition;

    public CorrelationCount(Searches searches, CorrelationCountProcessorConfig configuration, AggregationSearch.Factory aggregationSearchFactory, EventDefinition eventDefinition) {
        this.searches = searches;
        this.configuration = configuration;
        this.thresholds = new Thresholds(configuration);
        this.aggregationSearchFactory = aggregationSearchFactory;
        this.eventDefinition = eventDefinition;
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

    public String buildSearchQuery(String matchedFieldValue) {
        List<String> nextFields = new ArrayList<>(configuration.groupingFields());
        String firstField = nextFields.remove(0);
        String searchQuery = this.configuration.searchQuery();
        for (String field: nextFields) {
            matchedFieldValue = matchedFieldValue.replaceFirst(" - ", " AND " + field + ": ");
        }
        String globalSearchQuery = (searchQuery + " AND " + firstField + ": " + matchedFieldValue);
        LOG.debug("[DEV] buildSearchQuery: matchedTerms={}", globalSearchQuery); // TODO remove this log line
        return globalSearchQuery;
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

    public Map<String, Long[]> getMatchedTerms(TermsResult termResult, TermsResult termResultAdditionalStream) {
        Map<String, Long[]> matchedTerms = new HashMap<>();
        for (Map.Entry<String, Long> term: termResult.terms().entrySet()) {
            Long termAdditionalStreamValue = termResultAdditionalStream.terms().getOrDefault(term.getKey(), 0L);
            matchedTerms.put(term.getKey(), new Long[]{term.getValue(), termAdditionalStreamValue});
        }
        for (Map.Entry<String, Long> termAdditionalStream: termResultAdditionalStream.terms().entrySet()) {
            if (!matchedTerms.containsKey(termAdditionalStream.getKey())) {
                matchedTerms.put(termAdditionalStream.getKey(), new Long[]{0L, termAdditionalStream.getValue()});
            }
        }
        if (LOG.isDebugEnabled()) { // TODO remove this log line
            //getMatchedTerms: matchedTerms=2
            //sourceMessagesForEvent: key=127.0.0.7, value=[4, 4]
            //sourceMessagesForEvent: key=127.0.0.1, value=[4, 4]
            LOG.debug("[DEV] getMatchedTerms: matchedTerms={}", matchedTerms.size());
            matchedTerms.forEach((key, value) -> LOG.debug("[DEV] sourceMessagesForEvent: key={}, value={}", key, Arrays.deepToString(value)));
        }

        return matchedTerms;
    }

    /**
     * get count of matching alerts for the configuration default query.
     *
     * @param timerange {@link TimeRange}
     * @param stream    ID of the filtered stream
     * @return the count response
     */
    private CountResult searchCount(TimeRange timerange, String stream) {
        String filter = HEADER_STREAM + stream;
        return this.searches.count(this.configuration.searchQuery(), timerange, filter);
    }

    private CorrelationCountCheckResult runCheckCorrelationCount(TimeRange timerange) {
        CountResult resultMainStream = searchCount(timerange, this.configuration.stream());
        CountResult resultAdditionalStream = searchCount(timerange, this.configuration.additionalStream());

        if (!this.thresholds.areReached(resultMainStream.count(), resultAdditionalStream.count())) {
            return new CorrelationCountCheckResult("", new ArrayList<>());
        }

        List<MessageSummary> summariesMainStream = search(this.configuration.searchQuery(), this.configuration.stream(), timerange);
        List<MessageSummary> summariesAdditionalStream = search(this.configuration.searchQuery(), this.configuration.additionalStream(), timerange);

        if (!isRuleTriggered(summariesMainStream, summariesAdditionalStream)) {
            return new CorrelationCountCheckResult("", new ArrayList<>());
        }

        List<MessageSummary> summaries = Lists.newArrayList();
        summaries.addAll(summariesMainStream);
        summaries.addAll(summariesAdditionalStream);
        String resultDescription = getResultDescription(resultMainStream.count(), resultAdditionalStream.count());
        return new CorrelationCountCheckResult(resultDescription, summaries);
    }

    public TermsResult getTerms(String stream, TimeRange timeRange, long limit) {
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
        try {
            AggregationResult result = search.doSearch();
            return convertResult(config, result);
        } catch (EventProcessorException e) {
            e.printStackTrace();
        }  catch (IllegalArgumentException e) {
            LOG.error("Error when converting result: {}", e.getMessage());
            LOG.info("Complementary information in case of exception, timerange: {}, {}", timeRange.getFrom(), timeRange.getTo());
        }

        return convertResult(config, null); // TODO improve error case?
    }

    private TermsResult convertResult(AggregationEventProcessorConfig config, AggregationResult result) {
        if (LOG.isDebugEnabled()) { // TODO remove this log line
// AggregationEventProcessorConfig#query=message:bob*,groupBy=[source]
            LOG.debug("[DEV] convertResult: AggregationEventProcessorConfig#query={},groupBy={}", config.query(), Arrays.deepToString(config.groupBy().toArray()));
// AggregationResult#totalAggregatedMessages=8
            LOG.debug("[DEV] convertResult: AggregationResult#totalAggregatedMessages={}", result.totalAggregatedMessages());
            // AggregationResult#effectiveTimerange=AbsoluteRange{type=absolute, from=2021-10-06T12:57:11.196Z, to=2021-10-06T13:02:11.195Z}
            LOG.debug("[DEV] convertResult: AggregationResult#effectiveTimerange={}", result.effectiveTimerange());
// AggregationResult#sourceStreams=[000000000000000000000001, 6153f2974eb75f06e159e2e1, 615bfe2df4dca616fb45950f]
            LOG.debug("[DEV] convertResult: AggregationResult#sourceStreams={}", Arrays.deepToString(result.sourceStreams().toArray()));
            for (AggregationKeyResult aggregationKeyResult : result.keyResults()) {
                // AggregationResult#aggregationKeyResult#key=[127.0.0.1]
                // AggregationResult#aggregationKeyResult#seriesValues#value=4.0
                // AggregationResult#aggregationKeyResult#seriesValues#key=[127.0.0.1]
                // AggregationResult#aggregationKeyResult#seriesValues#series#field=Optional[source],id=correlation_idsource,function=COUNT
                LOG.debug("[DEV] convertResult: AggregationResult#aggregationKeyResult#key={}", Arrays.deepToString(aggregationKeyResult.key().toArray()));
                aggregationKeyResult.seriesValues().forEach(aggregationSeriesValue -> {
                    LOG.debug("[DEV] convertResult: AggregationResult#aggregationKeyResult#seriesValues#value={}", aggregationSeriesValue.value());
                    LOG.debug("[DEV] convertResult: AggregationResult#aggregationKeyResult#seriesValues#key={}", Arrays.deepToString(aggregationSeriesValue.key().toArray()));
                    // It looks like if series is the same for all seriesValues
                    LOG.debug("[DEV] convertResult: AggregationResult#aggregationKeyResult#seriesValues#series#field={},id={},function={}", aggregationSeriesValue.series().field(), aggregationSeriesValue.series().id(), aggregationSeriesValue.series().function());
                });
                // AggregationResult#aggregationKeyResult#key=[127.0.0.7]
                // AggregationResult#aggregationKeyResult#seriesValues#value=4.0
                // AggregationResult#aggregationKeyResult#seriesValues#key=[127.0.0.7]
                // AggregationResult#aggregationKeyResult#seriesValues#series#field=Optional[source],id=correlation_idsource,function=COUNT
            }

        }
        ImmutableMap.Builder<String, Long> terms = ImmutableMap.builder();
        long total = 0;
        if (null != result) {
            total = result.totalAggregatedMessages();
            result.keyResults().forEach(keyResult -> {
                keyResult.seriesValues().forEach(seriesValue -> {
                    String key = buildTermKey(seriesValue.key());
                    Long value = Double.valueOf(seriesValue.value()).longValue();
                    terms.put(key, value);
                });
            });
        }
        return TermsResult.create(0, terms.build(), 0, 0, total, config.query());
    }

    private String buildTermKey(Collection<String> keys) {
        StringBuilder builder = new StringBuilder();
        keys.forEach(key -> {
            if (0 < builder.length()) {
                builder.append(" - ");
            }
            builder.append(key);
        });
        return builder.toString();
    }

    private CorrelationCountCheckResult runCheckCorrelationWithFields(TimeRange timerange) {
        boolean ruleTriggered = false;
        // Get matching terms in main stream
        TermsResult termResult = getTerms(this.configuration.stream(), timerange, SEARCH_LIMIT);
        // Get matching terms in additional stream
        TermsResult termResultAdditionalStream = getTerms(this.configuration.additionalStream(), timerange, SEARCH_LIMIT);
        Map<String, Long[]> matchedTerms = getMatchedTerms(termResult, termResultAdditionalStream);

        long countFirstMainStream = 0;
        long countFirstAdditionalStream = 0;
        boolean isFirstTriggered = true;
        List<MessageSummary> summaries = Lists.newArrayList();
        for (Map.Entry<String, Long[]> matchedTerm: matchedTerms.entrySet()) {
            Long[] counts = matchedTerm.getValue();
            if (!this.thresholds.areReached(counts[0], counts[1])) {
                continue;
            }
            String matchedFieldValue = matchedTerm.getKey();
            String searchQuery = buildSearchQuery(matchedFieldValue);
            List<MessageSummary> summariesMainStream = search(searchQuery, this.configuration.stream(), timerange);
            List<MessageSummary> summariesAdditionalStream = search(searchQuery, this.configuration.additionalStream(), timerange);

            if (isRuleTriggered(summariesMainStream, summariesAdditionalStream)) {
                ruleTriggered = true;
                if (isFirstTriggered) {
                    countFirstMainStream = counts[0];
                    countFirstAdditionalStream = counts[1];
                    isFirstTriggered = false;
                }
                summaries.addAll(summariesMainStream);
                summaries.addAll(summariesAdditionalStream);
            }
        }

        if (ruleTriggered) {
            String resultDescription = getResultDescription(countFirstMainStream, countFirstAdditionalStream);
            return new CorrelationCountCheckResult(resultDescription, summaries);
        }
        return new CorrelationCountCheckResult("", new ArrayList<>());
    }

    public CorrelationCountCheckResult runCheck(TimeRange timerange) {
        // TODO should avoid having two different implementations
        if (this.configuration.groupingFields().isEmpty()) {
            return runCheckCorrelationCount(timerange);
        } else {
            return runCheckCorrelationWithFields(timerange);
        }
    }
}
