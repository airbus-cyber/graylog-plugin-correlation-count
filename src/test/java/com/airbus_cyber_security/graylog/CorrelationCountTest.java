package com.airbus_cyber_security.graylog;

import org.graylog2.indexer.results.CountResult;
import org.graylog2.plugin.Tools;
import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
import org.graylog2.plugin.streams.Stream;
import org.junit.Test;

import com.airbus_cyber_security.graylog.CorrelationCount;

import java.util.Locale;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CorrelationCountTest extends AlertConditionTest {
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
        searchCountShouldReturn(count, additionalStreamCount);
        searchResultShouldReturn();
        // AlertCondition was never triggered before
        final AlertCondition.CheckResult result = messageCountAlertCondition.runCheck();

        if (triggered) {
        	  String resultDescription = "The additional stream had " + additionalStreamCount + " messages with trigger condition " 
          			+ additionalStreamType.toString().toLowerCase(Locale.ENGLISH) + " than " + additionalStreamThreshold 
          			+ " messages " + "and" + " the main stream had " + count + " messages with trigger condition " 
          			+ type.toString().toLowerCase(Locale.ENGLISH) + " than " + threshold + " messages in the last " + "0" + " minutes"
          			+ ". (Current grace time: " + "0" + " minutes)";
              
            assertTriggered(messageCountAlertCondition, result);
            assertEquals("Matching messages ", 2, result.getMatchingMessages().size());
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

    private CorrelationCount getConditionWithParameters(CorrelationCount.ThresholdType type, Integer threshold,
    		CorrelationCount.ThresholdType additionalStreamType, Integer additionalStreamThreshold) {
        Map<String, Object> parameters = simplestParameterMap(type, threshold, additionalStreamType, additionalStreamThreshold);
        return getCorrelationCount(parameters, alertConditionTitle);
    }

    private Map<String, Object> simplestParameterMap(CorrelationCount.ThresholdType type, Integer threshold,
    		CorrelationCount.ThresholdType additionalStreamType, Integer additionalStreamThreshold) {
        return getParametersMap(0, 0, type, threshold, additionalStreamType, additionalStreamThreshold);
    }

    private void searchCountShouldReturn(long count, long additionalStreamCount) {
        final CountResult countResult = mock(CountResult.class);
        when(countResult.count()).thenReturn(count, additionalStreamCount);

        when(searches.count(anyString(), any(TimeRange.class), anyString())).thenReturn(countResult);
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
        parameters.put("additional_threshold", threshold);
        parameters.put("messages_order", CorrelationCount.OrderType.ANY.toString());
        
        return parameters;
    }
}
