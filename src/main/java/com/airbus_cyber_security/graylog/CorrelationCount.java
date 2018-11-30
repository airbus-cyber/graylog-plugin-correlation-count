package com.airbus_cyber_security.graylog;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.annotation.Nullable;
import javax.inject.Inject;

import org.graylog2.alerts.AbstractAlertCondition;
import org.graylog2.indexer.IndexSetRegistry;
import org.graylog2.indexer.indices.Indices;
import org.graylog2.indexer.results.CountResult;
import org.graylog2.indexer.results.ResultMessage;
import org.graylog2.indexer.results.SearchResult;
import org.graylog2.indexer.results.TermsResult;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.indexer.searches.Sorting;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.Tools;
import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.configuration.ConfigurationRequest;
import org.graylog2.plugin.configuration.fields.ConfigurationField;
import org.graylog2.plugin.configuration.fields.DropdownField;
import org.graylog2.plugin.configuration.fields.ListField;
import org.graylog2.plugin.configuration.fields.NumberField;
import org.graylog2.plugin.configuration.fields.TextField;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.graylog2.plugin.indexer.searches.timeranges.InvalidRangeParametersException;
import org.graylog2.plugin.indexer.searches.timeranges.RelativeRange;
import org.graylog2.plugin.streams.Stream;
import org.graylog2.streams.StreamService;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.Lists;
import com.google.inject.assistedinject.Assisted;
import com.google.inject.assistedinject.AssistedInject;

public class CorrelationCount extends AbstractAlertCondition {
    private static final Logger LOG = LoggerFactory.getLogger(CorrelationCount.class.getSimpleName());
    
    private static final String FIELD_ADDITIONAL_STREAM = "additional_stream";
    private static final String FIELD_TIME = "time";
    private static final String FIELD_ADDITIONAL_THRESHOLD_TYPE = "additional_threshold_type";
    private static final String FIELD_ADDITIONAL_THRESHOLD = "additional_threshold";
    private static final String FIELD_MAIN_THRESHOLD_TYPE = "main_threshold_type";
    private static final String FIELD_MAIN_THRESHOLD = "main_threshold";
    private static final String FIELD_GROUPING_FIELDS = "grouping_fields";
    private static final String FIELD_ORDER = "messages_order";
    private static final String FIELD_COMMENT = "comment";
 
    private static final String HEADER_STREAM = "streams:";
    private static final String QUERY = "*";
    
    enum ThresholdType {

        MORE("more than"),
        LESS("less than");

        private final String description;

        ThresholdType(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }
    
    enum OrderType {

        ANY("any order"),
        BEFORE("before"),
    	AFTER("after");
    	
        private final String description;

        OrderType(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }
    
    private final Searches searches;
    private final int time;
    private final ThresholdType thresholdType;
    private final int threshold;
    private final String additionalStreamID;
    private final ThresholdType additionalStreamThresholdType;
    private final int additionalStreamThreshold;
    private final List<String> fields;
    private final OrderType messagesOrder;
    
    public interface Factory extends AlertCondition.Factory {
        @Override
        CorrelationCount create(Stream stream,
                                               @Assisted("id") String id,
                                               DateTime createdAt,
                                               @Assisted("userid") String creatorUserId,
                                               Map<String, Object> parameters,
                                               @Assisted("title") @Nullable String title);

        @Override
        Config config();

        @Override
        Descriptor descriptor();
    }

    public static class Config implements AlertCondition.Config {
        private final StreamService streamService;
        private final Indices indices;
        private final IndexSetRegistry indexSetRegistry;
        
    	 @Inject
    	 public Config(StreamService streamService, Indices indices, IndexSetRegistry indexSetRegistry) {
    	        this.streamService = streamService;
            	this.indices = indices;
            	this.indexSetRegistry = indexSetRegistry;
    	}

        @Override
        public ConfigurationRequest getRequestedConfiguration() {
        	final List<Stream> allStreams = streamService.loadAll();
        	Map<String, String> mapStreams = new HashMap<>();
        	for (Stream stream : allStreams) {
        		mapStreams.put(stream.getId(), stream.getTitle());
			}
        	
        	final String[] writeIndexWildcards = indexSetRegistry.getIndexWildcards();
            final Set<String> listFields = indices.getAllMessageFields(writeIndexWildcards);    
            final Map<String, String> mapFields = listFields.stream().collect(Collectors.toMap(x -> x, x -> x));
            
            final ConfigurationRequest configurationRequest = ConfigurationRequest.createWithFields(
            		new DropdownField(
                            FIELD_ADDITIONAL_STREAM,
                            "Additional Stream",
                            "",
                        	mapStreams.entrySet().stream().sorted(Map.Entry.comparingByValue()).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue,(e1, e2) -> e1, LinkedHashMap::new)),
                            "Select the stream to correlate with the main stream",
                            ConfigurationField.Optional.NOT_OPTIONAL),
            		new DropdownField(
                            FIELD_ADDITIONAL_THRESHOLD_TYPE,
                            "Additional Threshold Type",
                            ThresholdType.MORE.toString(),
                            Arrays.stream(ThresholdType.values()).collect(Collectors.toMap(Enum::toString, ThresholdType::getDescription)),
                            "Select condition to trigger alert: when there are more or less messages in the additional stream than the threshold",
                            ConfigurationField.Optional.NOT_OPTIONAL),
                    new NumberField(FIELD_ADDITIONAL_THRESHOLD, "Additional Threshold", 0.0, 
                    		"Value which triggers an alert if crossed", 
                    		ConfigurationField.Optional.NOT_OPTIONAL),
                    new DropdownField(
                            FIELD_MAIN_THRESHOLD_TYPE,
                            "Main Threshold Type",
                            ThresholdType.MORE.toString(),
                            Arrays.stream(ThresholdType.values()).collect(Collectors.toMap(Enum::toString, ThresholdType::getDescription)),
                            "Select condition to trigger alert: when there are more or less messages in the main stream than the threshold",
                            ConfigurationField.Optional.NOT_OPTIONAL),
                    new NumberField(FIELD_MAIN_THRESHOLD, "Main Threshold", 0.0, 
                    		"Value which triggers an alert if crossed", 
                    		ConfigurationField.Optional.NOT_OPTIONAL),
            		new NumberField(FIELD_TIME, "Time Range", 5, 
                    		"Evaluate the condition for all messages received in the given number of minutes", 
                    		ConfigurationField.Optional.NOT_OPTIONAL),
                    new ListField(FIELD_GROUPING_FIELDS, "Grouping Fields", 
                    		Collections.emptyList(), 
                    		mapFields.entrySet().stream().sorted(Map.Entry.comparingByValue()).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue,(e1, e2) -> e1, LinkedHashMap::new)),
                    		"Fields that should be checked to count messages with the same values", 
                    		ConfigurationField.Optional.OPTIONAL,
                    		ListField.Attribute.ALLOW_CREATE),
		            new DropdownField(
		            		FIELD_ORDER,
		                    "Messages Order",
		                    OrderType.ANY.toString(),
		                    Arrays.stream(OrderType.values()).collect(Collectors.toMap(Enum::toString, OrderType::getDescription)),
		                    "Select condition to trigger alert: when the messages of the additional stream come in any order relative to/before/after the messages of the main stream",
		                    ConfigurationField.Optional.NOT_OPTIONAL),
		            new TextField(FIELD_COMMENT,
		                    "Comment",
		                    "",
		                    "Comment about the configuration",
		                    ConfigurationField.Optional.OPTIONAL));
            
            configurationRequest.addFields(AbstractAlertCondition.getDefaultConfigurationFields());
            return configurationRequest;
        }
    }

    public static class Descriptor extends AlertCondition.Descriptor {
        public Descriptor() {
            super(
                "Correlation Count Alert Condition",
                "https://www.airbus-cyber-security.com",
                "This condition is triggered when the number of messages in the main stream is higher/lower than a defined threshold and "
                + "when the number of messages in the additional stream is higher/lower than another defined threshold in a given time range."
            );
        }
    }

	@AssistedInject
    public CorrelationCount(Searches searches,
                                           @Assisted Stream stream,
                                           @Nullable @Assisted("id") String id,
                                           @Assisted DateTime createdAt,
                                           @Assisted("userid") String creatorUserId,
                                           @Assisted Map<String, Object> parameters,
                                           @Assisted("title") @Nullable String title) {
        super(stream, id, CorrelationCount.class.getCanonicalName(), createdAt, creatorUserId, parameters, title);    
        this.searches = searches;
        this.time = Tools.getNumber(parameters.get(FIELD_TIME), 5).intValue();
        this.thresholdType = ThresholdType.valueOf((String) parameters.get(FIELD_MAIN_THRESHOLD_TYPE));
        this.threshold = Tools.getNumber(parameters.get(FIELD_MAIN_THRESHOLD), 0).intValue();    
        this.additionalStreamID = (String) parameters.get(FIELD_ADDITIONAL_STREAM);
        this.additionalStreamThresholdType = ThresholdType.valueOf((String) parameters.get(FIELD_ADDITIONAL_THRESHOLD_TYPE));
        this.additionalStreamThreshold = Tools.getNumber(parameters.get(FIELD_ADDITIONAL_THRESHOLD), 0).intValue();  
        this.fields = (List<String>) parameters.getOrDefault(FIELD_GROUPING_FIELDS,Collections.emptyList());
        this.messagesOrder = OrderType.valueOf((String) parameters.getOrDefault(FIELD_ORDER, OrderType.ANY.toString()));
    }

    @Override
    public String getDescription() {
        return "time: " + time
                + ", main_threshold_type: " + thresholdType.toString().toLowerCase(Locale.ENGLISH)
                + ", main_threshold: " + threshold
                + ", grace: " + grace
                + ", repeat notifications: " + repeatNotifications;
    }
    
    private boolean isTriggered(ThresholdType thresholdType, int threshold, long count) {
    	return (((thresholdType == ThresholdType.MORE) && (count > threshold)) || 
    			((thresholdType == ThresholdType.LESS) && (count < threshold)));
    }
    
    private void addSearchMessages(List<MessageSummary> summaries, String searchQuery, String filter, AbsoluteRange range) {
    	final SearchResult backlogResult = searches.search(searchQuery, filter,
				range, getBacklog(), 0, new Sorting(Message.FIELD_TIMESTAMP, Sorting.Direction.DESC));
		for (ResultMessage resultMessage : backlogResult.getResults()) {
			summaries.add(new MessageSummary(resultMessage.getIndex(), resultMessage.getMessage()));
		}
    }
    
    private String buildSearchQuery(String firstField, List<String> nextFields, String matchedFieldValue) {
		for (String field : nextFields) {
			matchedFieldValue = matchedFieldValue.replaceFirst(" - ", " AND " + field + ": ");
		}
		return (QUERY + " AND " + firstField + ": " + matchedFieldValue);
    }
    
    private List<DateTime> getListOrderTimestamp(List<MessageSummary> summaries){
    	List<DateTime> listDate = new ArrayList<>();
    	for (MessageSummary messageSummary : summaries) {
    		listDate.add(messageSummary.getTimestamp());
    	}
    	Collections.sort(listDate);
    	if(messagesOrder.equals(OrderType.AFTER)) {
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
    	List<DateTime> listDateFirstStream = getListOrderTimestamp(summariesFirstStream);
    	List<DateTime> listDateSecondStream = getListOrderTimestamp(summariesSecondStream);
    	
    	for (DateTime dateFirstStream : listDateFirstStream) {
    		int countSecondStream = 0;
	    	for (DateTime dateSecondStream : listDateSecondStream) {
	    		if(	(messagesOrder.equals(OrderType.BEFORE) && dateSecondStream.isBefore(dateFirstStream)) ||
	    			(messagesOrder.equals(OrderType.AFTER) && dateSecondStream.isAfter(dateFirstStream))){
	    			countSecondStream++;
	    		}else {
	    			break;
	    		}
	    	}
	    	if(isTriggered(thresholdType,threshold,countFirstStream) && isTriggered(additionalStreamThresholdType,additionalStreamThreshold,countSecondStream)) {
	    		return true;
	    	}
	    	countFirstStream--;
    	}
    	return false;
    }

    private String getResultDescription(long countMainStream, long countAdditionalStream) {
    	
    	String msgCondition;
    	if(messagesOrder.equals(OrderType.ANY)) {
    		msgCondition = "and";
    	} else {
    		msgCondition = messagesOrder.getDescription();
    	}
    	
    	String resultDescription = "The additional stream had " + countAdditionalStream + " messages with trigger condition " 
    			+ additionalStreamThresholdType.toString().toLowerCase(Locale.ENGLISH) + " than " + additionalStreamThreshold 
    			+ " messages " + msgCondition + " the main stream had " + countMainStream + " messages with trigger condition "  
    			+ thresholdType.toString().toLowerCase(Locale.ENGLISH) + " than " + threshold + " messages in the last " + time + " minutes";
    	
    	if(!fields.isEmpty()) {
    		resultDescription = resultDescription+" with the same value of the fields " + String.join(", ",fields);
    	}
    	
    	return resultDescription+". (Current grace time: " + grace + " minutes)";
    }
    
    private boolean isRuleTriggered(List<MessageSummary> summariesMainStream, List<MessageSummary> summariesAdditionalStream) {
    	boolean ruleTriggered = true;
		if(messagesOrder.equals(OrderType.BEFORE) || messagesOrder.equals(OrderType.AFTER)) {
			ruleTriggered = checkOrderSecondStream(summariesMainStream, summariesAdditionalStream);
		}
		return ruleTriggered;
    }

    private CheckResult runCheckCorrelationCount() {
    	try {
    		final RelativeRange relativeRange = RelativeRange.create(time * 60);
    		final AbsoluteRange range = AbsoluteRange.create(relativeRange.getFrom(), relativeRange.getTo());
    		final String filterMainStream = HEADER_STREAM + stream.getId();
    		final CountResult resultMainStream = searches.count(QUERY, range, filterMainStream);
    		final String filterAdditionalStream = HEADER_STREAM + additionalStreamID;
    		final CountResult resultAdditionalStream = searches.count(QUERY, range, filterAdditionalStream);

    		LOG.debug("Alert check <{}> result: [{}]", id, resultAdditionalStream.count());

    		if(isTriggered(thresholdType, threshold, resultMainStream.count()) && isTriggered(additionalStreamThresholdType, additionalStreamThreshold, resultAdditionalStream.count())) {
    			final List<MessageSummary> summaries = Lists.newArrayList();
				final List<MessageSummary> summariesMainStream = Lists.newArrayList();
				final List<MessageSummary> summariesAdditionalStream = Lists.newArrayList();
				
    			if (getBacklog() > 0 || !messagesOrder.equals(OrderType.ANY)) {
    				addSearchMessages(summariesMainStream, QUERY, filterMainStream, range);
    				addSearchMessages(summariesAdditionalStream, QUERY, filterAdditionalStream, range);
    			}
    			
    			if(isRuleTriggered(summariesMainStream, summariesAdditionalStream)) {
	    			if(getBacklog() > 0) {
						summaries.addAll(summariesMainStream);
						summaries.addAll(summariesAdditionalStream);
					}
	    			final String resultDescription = getResultDescription(resultMainStream.count(), resultAdditionalStream.count());
	    			return new CheckResult(true, this, resultDescription, Tools.nowUTC(), summaries);
    			}
    		}
    		return new NegativeCheckResult();
    	} catch (InvalidRangeParametersException e) {
    		LOG.error("Invalid timerange.", e);
    		return null;
    	}
    }
    
    private Map<String, Long[]> getMatchedTerms(TermsResult termResult, TermsResult termResultAdditionalStrem){
    	
    	Map<String, Long[]> matchedTerms = new HashMap<>();
		for (Map.Entry<String, Long> term : termResult.getTerms().entrySet()) {		
			Long termAdditionalStreamValue = termResultAdditionalStrem.getTerms().getOrDefault(term.getKey(), 0L);
			matchedTerms.put(term.getKey(), new Long[] {term.getValue(), termAdditionalStreamValue});
		}
		for (Map.Entry<String, Long> termAdditionalStream : termResultAdditionalStrem.getTerms().entrySet()) {	
			if(!matchedTerms.containsKey(termAdditionalStream.getKey())){
    			matchedTerms.put(termAdditionalStream.getKey(), new Long[] {0L, termAdditionalStream.getValue()});
			}
		}
		
		return matchedTerms;
    }

    private CheckResult runCheckCorrelationWithFields() {
    	try {
    		final RelativeRange relativeRange = RelativeRange.create(time * 60);
    		final AbsoluteRange range = AbsoluteRange.create(relativeRange.getFrom(), relativeRange.getTo());
    		final String filterMainStream = HEADER_STREAM + stream.getId();
    		final String filterAdditionalStream = HEADER_STREAM + additionalStreamID;
    		boolean ruleTriggered=false;
    		Integer backlogSize = getBacklog();
    		boolean backlogEnabled = false;
    		int searchLimit = 100;
    		if(backlogSize != null && backlogSize > 0) {
    			backlogEnabled = true;
    			searchLimit = backlogSize;
    		}

    		List<String> nextFields = new ArrayList<>(fields);
    		String firstField = fields.get(0);
    		nextFields.remove(0);

    		TermsResult termResult = searches.terms(firstField, nextFields, searchLimit, QUERY, filterMainStream, range, Sorting.Direction.DESC);
    		TermsResult termResultAdditionalStrem = searches.terms(firstField, nextFields, searchLimit, QUERY, filterAdditionalStream, range, Sorting.Direction.DESC);
    		Map<String, Long[]> matchedTerms = getMatchedTerms(termResult, termResultAdditionalStrem);
    		
    		long countFirstMainStream = 0;
    		long countFirstAdditionalStream = 0;
    		boolean isFirstTriggered = true;
    		final List<MessageSummary> summaries = Lists.newArrayList();
    		for (Map.Entry<String, Long[]> matchedTerm  : matchedTerms.entrySet()) {
    			String matchedFieldValue = matchedTerm.getKey();
    			Long[] counts = matchedTerm.getValue();

    			if(isTriggered(thresholdType,threshold,counts[0]) && isTriggered(additionalStreamThresholdType,additionalStreamThreshold,counts[1])) {	
    				final List<MessageSummary> summariesMainStream = Lists.newArrayList();
    				final List<MessageSummary> summariesAdditionalStream = Lists.newArrayList();
    				
    				if (backlogEnabled ||  !messagesOrder.equals(OrderType.ANY)) {
    					String searchQuery = buildSearchQuery(firstField, nextFields, matchedFieldValue);

        				addSearchMessages(summariesMainStream, searchQuery, filterMainStream, range);
        				addSearchMessages(summariesAdditionalStream, searchQuery, filterAdditionalStream, range);
    				}
    				
        			if(isRuleTriggered(summariesMainStream, summariesAdditionalStream)) {
        				ruleTriggered = true;
	        			if(isFirstTriggered) {
	        				countFirstMainStream = counts[0];
	        				countFirstAdditionalStream = counts[1];
	        				isFirstTriggered = false;
	        			}
		    			if(backlogSize > 0) {
							summaries.addAll(summariesMainStream);
							summaries.addAll(summariesAdditionalStream);
						}		
	    			}
    			} 	
    		}
    		
    		if(ruleTriggered) {
    			final String resultDescription = getResultDescription(countFirstMainStream, countFirstAdditionalStream);
    			return new CheckResult(true, this, resultDescription, Tools.nowUTC(), summaries);
    		}
    		return new NegativeCheckResult();
    	} catch (InvalidRangeParametersException e) {
    		LOG.error("Invalid timerange.", e);
    		return null;
    	}
    }
    
    /**
     * Check if the conditions are triggered
     * 
     * This condition is triggered when the number of messages in the main stream is higher/lower than a defined threshold and
     * when the number of messages in the additional stream is higher/lower than another defined threshold in a given time range.
     * 
     * @return CheckResult 
     * 					Result Description and list of messages that satisfy the conditions
     */
    @Override
    public CheckResult runCheck() { 
    	if(fields.isEmpty()) {
    		return runCheckCorrelationCount();
    	}else {
    		return runCheckCorrelationWithFields();
    	}
    }

}
