package com.airbus_cyber_security.graylog.events.processor.correlation.checks;

import com.airbus_cyber_security.graylog.events.processor.correlation.CorrelationCountProcessorConfig;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.Lists;
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

    private final Searches searches;
    private final CorrelationCountProcessorConfig configuration;
    private final Thresholds thresholds;

    public CorrelationCount(Searches searches, CorrelationCountProcessorConfig configuration) {
        this.searches = searches;
        this.configuration = configuration;
        this.thresholds = new Thresholds(configuration);
    }

    private static void addSearchMessages(Searches searches, List<MessageSummary> summaries, String searchQuery, String filter, TimeRange range) {
        final SearchResult backlogResult = searches.search(searchQuery, filter,
                range, SEARCH_LIMIT, 0, new Sorting(Message.FIELD_TIMESTAMP, Sorting.Direction.DESC));
        for (ResultMessage resultMessage : backlogResult.getResults()) {
            summaries.add(new MessageSummary(resultMessage.getIndex(), resultMessage.getMessage()));
        }
    }

    private static String buildSearchQuery(String firstField, List<String> nextFields, String matchedFieldValue, String searchQuery) {
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
    protected boolean checkOrderSecondStream(List<MessageSummary> summariesFirstStream, List<MessageSummary> summariesSecondStream, CorrelationCountProcessorConfig config) {
        int countFirstStream = summariesFirstStream.size();
        CorrelationCount.OrderType messagesOrder = CorrelationCount.OrderType.fromString(config.messagesOrder());
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

    private boolean isRuleTriggered(List<MessageSummary> summariesMainStream, List<MessageSummary> summariesAdditionalStream, CorrelationCountProcessorConfig config) {
        boolean ruleTriggered = true;
        if (CorrelationCount.OrderType.fromString(config.messagesOrder()).equals(CorrelationCount.OrderType.BEFORE)
                || CorrelationCount.OrderType.fromString(config.messagesOrder()).equals(CorrelationCount.OrderType.AFTER)) {
            ruleTriggered = checkOrderSecondStream(summariesMainStream, summariesAdditionalStream, config);
        }
        return ruleTriggered;
    }

    private static Map<String, Long[]> getMatchedTerms(TermsResult termResult, TermsResult termResultAdditionalStrem){

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

    public CorrelationCountCheckResult runCheckCorrelationCount(TimeRange timerange, Searches searches, CorrelationCountProcessorConfig config) {
        String filterMainStream = HEADER_STREAM + config.stream();
        CountResult resultMainStream = searches.count(config.searchQuery(), timerange, filterMainStream);
        String filterAdditionalStream = HEADER_STREAM + config.additionalStream();
        CountResult resultAdditionalStream = searches.count(config.searchQuery(), timerange, filterAdditionalStream);

        if (this.thresholds.areReached(resultMainStream.count(), resultAdditionalStream.count())) {
            List<MessageSummary> summaries = Lists.newArrayList();
            List<MessageSummary> summariesMainStream = Lists.newArrayList();
            List<MessageSummary> summariesAdditionalStream = Lists.newArrayList();

            if (!CorrelationCount.OrderType.valueOf(config.messagesOrder()).equals(CorrelationCount.OrderType.ANY)) {
                addSearchMessages(searches, summariesMainStream, config.searchQuery(), filterMainStream, timerange);
                addSearchMessages(searches, summariesAdditionalStream, config.searchQuery(), filterAdditionalStream, timerange);
            }

            if (isRuleTriggered(summariesMainStream, summariesAdditionalStream, config)) {
                summaries.addAll(summariesMainStream);
                summaries.addAll(summariesAdditionalStream);
                String resultDescription = getResultDescription(resultMainStream.count(), resultAdditionalStream.count(), config);
                return new CorrelationCountCheckResult(resultDescription, summaries);
            }
        }
        return new CorrelationCountCheckResult("", new ArrayList<>());
    }

    public CorrelationCountCheckResult runCheckCorrelationWithFields(TimeRange timerange, Searches searches, CorrelationCountProcessorConfig config) {
        String filterMainStream = HEADER_STREAM + config.stream();
        String filterAdditionalStream = HEADER_STREAM + config.additionalStream();
        boolean ruleTriggered = false;

        List<String> nextFields = new ArrayList<>(config.groupingFields());
        String firstField = config.groupingFields().iterator().next();
        nextFields.remove(0);

        TermsResult termResult = searches.terms(firstField, nextFields, SEARCH_LIMIT, config.searchQuery(), filterMainStream, timerange, Sorting.Direction.DESC);
        TermsResult termResultAdditionalStream = searches.terms(firstField, nextFields, SEARCH_LIMIT, config.searchQuery(), filterAdditionalStream, timerange, Sorting.Direction.DESC);
        Map<String, Long[]> matchedTerms = getMatchedTerms(termResult, termResultAdditionalStream);

        long countFirstMainStream = 0;
        long countFirstAdditionalStream = 0;
        boolean isFirstTriggered = true;
        final List<MessageSummary> summaries = Lists.newArrayList();
        for (Map.Entry<String, Long[]> matchedTerm: matchedTerms.entrySet()) {
            String matchedFieldValue = matchedTerm.getKey();
            Long[] counts = matchedTerm.getValue();

            if (this.thresholds.areReached(counts[0], counts[1])) {
                List<MessageSummary> summariesMainStream = Lists.newArrayList();
                List<MessageSummary> summariesAdditionalStream = Lists.newArrayList();

                if (!CorrelationCount.OrderType.valueOf(config.messagesOrder()).equals(CorrelationCount.OrderType.ANY)) {
                    String searchQuery = buildSearchQuery(firstField, nextFields, matchedFieldValue, config.searchQuery());

                    addSearchMessages(searches, summariesMainStream, searchQuery, filterMainStream, timerange);
                    addSearchMessages(searches, summariesAdditionalStream, searchQuery, filterAdditionalStream, timerange);
                }

                if (isRuleTriggered(summariesMainStream, summariesAdditionalStream, config)) {
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
            return runCheckCorrelationCount(timerange, this.searches, this.configuration);
        } else {
            return runCheckCorrelationWithFields(timerange, this.searches, this.configuration);
        }
    }
}
