package com.airbus_cyber_security.graylog;

import org.graylog2.indexer.results.TermsResult;
import org.graylog2.indexer.searches.Sorting.Direction;
import org.graylog2.plugin.Tools;
import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
import org.graylog2.plugin.streams.Stream;
import org.junit.Test;

import com.airbus_cyber_security.graylog.CorrelationCount;

import jersey.repackaged.com.google.common.collect.Lists;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CorrelationCountWithFieldTest extends AlertConditionTest {
    private final int threshold = 100;
    private final String REMOTE_STREAM_ID = "REMOTESTREAMMOCKID";

    @Test
    public void testConstructor() throws Exception {
        final Map<String, Object> parameters = getParametersMap(0, 0, CorrelationCount.ThresholdType.MORE, 0, 
        														CorrelationCount.ThresholdType.MORE, 0);

        final CorrelationCount messageCountAlertCondition = getCorrelationCount(parameters, alertConditionTitle);

        assertNotNull(messageCountAlertCondition);
        assertNotNull(messageCountAlertCondition.getDescription());
        final String thresholdType = (String) messageCountAlertCondition.getParameters().get("additional_threshold_type");
        assertEquals(thresholdType, thresholdType.toUpperCase(Locale.ENGLISH));
    }
    
    public void testRunCheck(CorrelationCount.ThresholdType type, Integer threshold,
    		CorrelationCount.ThresholdType additionalStreamType, Integer additionalStreamThreshold,
    		long count, long additionalStreamCount, boolean triggered) throws Exception {

        final CorrelationCount messageCountAlertCondition = getConditionWithParameters(type, threshold, additionalStreamType, additionalStreamThreshold);
        searchTermsShouldReturn(count, additionalStreamCount);
        searchResultShouldReturn();
        // AlertCondition was never triggered before
        final AlertCondition.CheckResult result = messageCountAlertCondition.runCheck();
        
        if (triggered) {       	 
        	 String resultDescription = "The additional stream had " + additionalStreamCount + " messages with trigger condition " 
           			+ additionalStreamType.toString().toLowerCase(Locale.ENGLISH) + " than " + additionalStreamThreshold 
           			+ " messages " + "and" + " the main stream had " + count + " messages with trigger condition " 
           			+ type.toString().toLowerCase(Locale.ENGLISH) + " than " + threshold + " messages in the last " + "0" + " minutes"
           			+ " with the same value of the fields " + String.join(", ", Lists.newArrayList("user","ip_src"))
           			+ ". (Current grace time: " + "0" + " minutes)";
        	 
            assertTriggered(messageCountAlertCondition, result);
            assertEquals("Matching messages ", 4, result.getMatchingMessages().size());
            assertEquals("Result Description ", resultDescription, result.getResultDescription());
        }else {
        	assertNotTriggered(result);
        }
    }
    
    @Test
    public void testRunCheckMorePositive() throws Exception {
    	testRunCheck(CorrelationCount.ThresholdType.MORE, threshold, CorrelationCount.ThresholdType.MORE, threshold, 
    			threshold+1L, threshold+1L, true);
    }


    @Test
    public void testRunCheckLessPositive() throws Exception {
    	testRunCheck(CorrelationCount.ThresholdType.LESS, threshold, CorrelationCount.ThresholdType.LESS, threshold, 
    			threshold-1L, threshold-1L, true);
    }

    @Test
    public void testRunCheckMoreNegative() throws Exception {
    	testRunCheck(CorrelationCount.ThresholdType.LESS, threshold, CorrelationCount.ThresholdType.MORE, threshold, 
    			threshold, threshold, false);
    }

    @Test
    public void testRunCheckLessNegative() throws Exception {
    	testRunCheck(CorrelationCount.ThresholdType.MORE, threshold, CorrelationCount.ThresholdType.LESS, threshold, 
    			threshold, threshold, false);
    }
    
    @Test
    public void testRunCheckLessNegativeNoAdditional() throws Exception {
    	testRunCheck(CorrelationCount.ThresholdType.MORE, 0, CorrelationCount.ThresholdType.LESS, 1, 1, 0, true);
    }
    
    @Test
    public void testRunCheckLessNegativeNoMain() throws Exception {
    	testRunCheck(CorrelationCount.ThresholdType.LESS, 1, CorrelationCount.ThresholdType.MORE, 0, 0, 1, true);
    }

    private CorrelationCount getConditionWithParameters(CorrelationCount.ThresholdType type, Integer threshold,
    		CorrelationCount.ThresholdType additionalStreamType, Integer additionalStreamThreshold) {
        Map<String, Object> parameters = simplestParameterMap(type, threshold, additionalStreamType, additionalStreamThreshold);
        return getCorrelationCount(parameters, alertConditionTitle);
    }

    private Map<String, Object> simplestParameterMap(CorrelationCount.ThresholdType type, Integer threshold,
    		CorrelationCount.ThresholdType additionalStreamType, Integer additionalStreamThreshold) {
        return getParametersMap(0, 0, type, threshold, additionalStreamType, additionalStreamThreshold);
    }

    
    private void searchTermsShouldReturn(long count, long countAdditional) {
        final TermsResult termsResult = mock(TermsResult.class);   
        Map<String, Long> terms = new HashMap<String, Long>();
        if(count > 0) {
	        terms.put("user - ip1", count);
	        terms.put("user - ip2", count);
        }
        
        Map<String, Long> termsAdd = new HashMap<String, Long>();
        if(countAdditional > 0) {
	        termsAdd.put("user - ip1", countAdditional);
	        termsAdd.put("user - ip2", countAdditional);
        }


        when(termsResult.getTerms()).thenReturn(terms).thenReturn(termsAdd);

		when(searches.terms(anyString(), anyList() , any(int.class), anyString(), anyString(), any(TimeRange.class), any(Direction .class))).thenReturn(termsResult);
		
    }   
    
    private CorrelationCount getCorrelationCount(Map<String, Object> parameters, String title) {
    	final Stream stream = mock(Stream.class);
    	when(stream.getTitle()).thenReturn("Additional Title");
    	
        return new CorrelationCount(
            searches,
            stream,
            CONDITION_ID,
            Tools.nowUTC(),
            STREAM_CREATOR,
            parameters,
            title);
    }

    private Map<String, Object> getParametersMap(Integer grace, Integer time, CorrelationCount.ThresholdType type, Number threshold,
    		CorrelationCount.ThresholdType additionalStreamType, Number additionalStreamThreshold) {
        Map<String, Object> parameters = super.getParametersMap(grace, time, threshold);
        parameters.put("main_threshold_type", type.toString());
        parameters.put("additional_stream",REMOTE_STREAM_ID);
        parameters.put("additional_threshold_type", additionalStreamType.toString());
        parameters.put("additional_threshold", additionalStreamThreshold);
        List<String> fields = new ArrayList<>();
        fields.add("user");
        fields.add("ip_src");
        parameters.put("grouping_fields", fields);
        return parameters;
    }
    
    
}
