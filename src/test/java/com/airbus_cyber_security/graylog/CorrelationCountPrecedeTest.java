package com.airbus_cyber_security.graylog;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.graylog2.indexer.searches.Searches;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.Tools;
import org.graylog2.plugin.streams.Stream;
import org.joda.time.DateTime;
import org.junit.Test;
import org.mockito.Mock;

import com.airbus_cyber_security.graylog.CorrelationCount;

public class CorrelationCountPrecedeTest extends AlertConditionTest {

	private final int threshold = 4;
    private final String REMOTE_STREAM_ID = "REMOTESTREAMMOCKID";
	
	@Mock
    protected Stream stream;
    @Mock
    protected Searches searches;
    
	@Test
	public void testCheckOrderStreamBefore() {
		Map<String, Object> parameters = getParametersMap(0,10,CorrelationCount.ThresholdType.MORE,0,CorrelationCount.ThresholdType.MORE,threshold,
				CorrelationCount.OrderType.BEFORE.toString());
		final CorrelationCount correlationCountAlertCondition =  getCorrelationCount(parameters, "title");
		 
		List<MessageSummary> summariesStream1 = new ArrayList<MessageSummary>();
		summariesStream1.add(new MessageSummary("0", new Message("message", "source", new DateTime(600))));
		List<MessageSummary> summariesStream2 = new ArrayList<MessageSummary>();
		summariesStream2.add(new MessageSummary("0", new Message("message", "source", new DateTime(100))));
		summariesStream2.add(new MessageSummary("1", new Message("message", "source", new DateTime(200))));
		summariesStream2.add(new MessageSummary("2", new Message("message", "source", new DateTime(300))));
		summariesStream2.add(new MessageSummary("3", new Message("message", "source", new DateTime(400))));
		summariesStream2.add(new MessageSummary("4", new Message("message", "source", new DateTime(500))));
		
		assertEquals(true, correlationCountAlertCondition.checkOrderSecondStream(summariesStream1, summariesStream2));
	}
	
	@Test
	public void testCheckOrderStreamBeforeFail() {
		Map<String, Object> parameters = getParametersMap(0,10,CorrelationCount.ThresholdType.MORE,0,CorrelationCount.ThresholdType.MORE,threshold,
				CorrelationCount.OrderType.BEFORE.toString());
		final CorrelationCount correlationCountAlertCondition =  getCorrelationCount(parameters, "title");
		 
		List<MessageSummary> summariesStream1 = new ArrayList<MessageSummary>();
		summariesStream1.add(new MessageSummary("0", new Message("message", "source", new DateTime(500))));
		List<MessageSummary> summariesStream2 = new ArrayList<MessageSummary>();
		summariesStream2.add(new MessageSummary("0", new Message("message", "source", new DateTime(100))));
		summariesStream2.add(new MessageSummary("1", new Message("message", "source", new DateTime(200))));
		summariesStream2.add(new MessageSummary("2", new Message("message", "source", new DateTime(300))));
		summariesStream2.add(new MessageSummary("3", new Message("message", "source", new DateTime(400))));
		summariesStream2.add(new MessageSummary("4", new Message("message", "source", new DateTime(600))));
		
		assertEquals(false, correlationCountAlertCondition.checkOrderSecondStream(summariesStream1, summariesStream2));
	}
	
	@Test
	public void testCheckOrderStreamBeforeThreshold() {
		Map<String, Object> parameters = getParametersMap(0,10,CorrelationCount.ThresholdType.MORE,1,CorrelationCount.ThresholdType.MORE,threshold,
				CorrelationCount.OrderType.BEFORE.toString());
		final CorrelationCount correlationCountAlertCondition =  getCorrelationCount(parameters, "title");
		 
		List<MessageSummary> summariesStream1 = new ArrayList<MessageSummary>();
		summariesStream1.add(new MessageSummary("0", new Message("message", "source", new DateTime(600))));
		summariesStream1.add(new MessageSummary("1", new Message("message", "source", new DateTime(700))));

		List<MessageSummary> summariesStream2 = new ArrayList<MessageSummary>();
		summariesStream2.add(new MessageSummary("0", new Message("message", "source", new DateTime(100))));
		summariesStream2.add(new MessageSummary("1", new Message("message", "source", new DateTime(200))));
		summariesStream2.add(new MessageSummary("2", new Message("message", "source", new DateTime(300))));
		summariesStream2.add(new MessageSummary("3", new Message("message", "source", new DateTime(400))));
		summariesStream2.add(new MessageSummary("4", new Message("message", "source", new DateTime(500))));
		
		assertEquals(true, correlationCountAlertCondition.checkOrderSecondStream(summariesStream1, summariesStream2));
	}
	
	@Test
	public void testCheckOrderStreamBeforeThresholdFail() {
		Map<String, Object> parameters = getParametersMap(0,10,CorrelationCount.ThresholdType.MORE,1,CorrelationCount.ThresholdType.MORE,threshold,
				CorrelationCount.OrderType.BEFORE.toString());
		final CorrelationCount correlationCountAlertCondition =  getCorrelationCount(parameters, "title");
		 
		List<MessageSummary> summariesStream1 = new ArrayList<MessageSummary>();
		summariesStream1.add(new MessageSummary("0", new Message("message", "source", new DateTime(500))));
		summariesStream1.add(new MessageSummary("1", new Message("message", "source", new DateTime(700))));

		List<MessageSummary> summariesStream2 = new ArrayList<MessageSummary>();
		summariesStream2.add(new MessageSummary("0", new Message("message", "source", new DateTime(100))));
		summariesStream2.add(new MessageSummary("1", new Message("message", "source", new DateTime(200))));
		summariesStream2.add(new MessageSummary("2", new Message("message", "source", new DateTime(300))));
		summariesStream2.add(new MessageSummary("3", new Message("message", "source", new DateTime(400))));
		summariesStream2.add(new MessageSummary("4", new Message("message", "source", new DateTime(600))));
		
		assertEquals(false, correlationCountAlertCondition.checkOrderSecondStream(summariesStream1, summariesStream2));
	}
	
	@Test
	public void testCheckOrderStreamBeforeThreshold2Fail() {
		Map<String, Object> parameters = getParametersMap(0,10,CorrelationCount.ThresholdType.MORE,1,CorrelationCount.ThresholdType.MORE,threshold,
				CorrelationCount.OrderType.BEFORE.toString());
		final CorrelationCount correlationCountAlertCondition =  getCorrelationCount(parameters, "title");
		 
		List<MessageSummary> summariesStream1 = new ArrayList<MessageSummary>();
		summariesStream1.add(new MessageSummary("0", new Message("message", "source", new DateTime(500))));
		summariesStream1.add(new MessageSummary("1", new Message("message", "source", new DateTime(1100))));

		List<MessageSummary> summariesStream2 = new ArrayList<MessageSummary>();
		summariesStream2.add(new MessageSummary("0", new Message("message", "source", new DateTime(100))));
		summariesStream2.add(new MessageSummary("1", new Message("message", "source", new DateTime(200))));
		summariesStream2.add(new MessageSummary("2", new Message("message", "source", new DateTime(300))));
		summariesStream2.add(new MessageSummary("3", new Message("message", "source", new DateTime(400))));
		summariesStream2.add(new MessageSummary("4", new Message("message", "source", new DateTime(600))));
		summariesStream2.add(new MessageSummary("5", new Message("message", "source", new DateTime(700))));
		summariesStream2.add(new MessageSummary("6", new Message("message", "source", new DateTime(800))));
		summariesStream2.add(new MessageSummary("7", new Message("message", "source", new DateTime(900))));
		summariesStream2.add(new MessageSummary("8", new Message("message", "source", new DateTime(1000))));
		
		assertEquals(false, correlationCountAlertCondition.checkOrderSecondStream(summariesStream1, summariesStream2));
	}
	
	@Test
	public void testCheckOrderStreamThreshold2Before() {
		Map<String, Object> parameters = getParametersMap(0,10,CorrelationCount.ThresholdType.MORE,1,CorrelationCount.ThresholdType.MORE,threshold,
				CorrelationCount.OrderType.BEFORE.toString());		 
		final CorrelationCount correlationCountAlertCondition =  getCorrelationCount(parameters, "title");
		 
		List<MessageSummary> summariesStream1 = new ArrayList<MessageSummary>();
		summariesStream1.add(new MessageSummary("0", new Message("message", "source", new DateTime(600))));
		summariesStream1.add(new MessageSummary("1", new Message("message", "source", new DateTime(1100))));

		List<MessageSummary> summariesStream2 = new ArrayList<MessageSummary>();
		summariesStream2.add(new MessageSummary("0", new Message("message", "source", new DateTime(100))));
		summariesStream2.add(new MessageSummary("1", new Message("message", "source", new DateTime(200))));
		summariesStream2.add(new MessageSummary("2", new Message("message", "source", new DateTime(300))));
		summariesStream2.add(new MessageSummary("3", new Message("message", "source", new DateTime(400))));
		summariesStream2.add(new MessageSummary("4", new Message("message", "source", new DateTime(500))));
		summariesStream2.add(new MessageSummary("5", new Message("message", "source", new DateTime(700))));
		summariesStream2.add(new MessageSummary("6", new Message("message", "source", new DateTime(800))));
		summariesStream2.add(new MessageSummary("7", new Message("message", "source", new DateTime(900))));
		summariesStream2.add(new MessageSummary("8", new Message("message", "source", new DateTime(1000))));
		
		assertEquals(true, correlationCountAlertCondition.checkOrderSecondStream(summariesStream1, summariesStream2));
	}
	
	@Test
	public void testCheckOrderStreamAfter() {
		Map<String, Object> parameters = getParametersMap(0,10,CorrelationCount.ThresholdType.MORE,threshold,CorrelationCount.ThresholdType.MORE,1,
				CorrelationCount.OrderType.AFTER.toString());
		final CorrelationCount correlationCountAlertCondition =  getCorrelationCount(parameters, "title");
		 
		List<MessageSummary> summariesStream1 = new ArrayList<MessageSummary>();
		summariesStream1.add(new MessageSummary("0", new Message("message", "source", new DateTime(600))));
		summariesStream1.add(new MessageSummary("1", new Message("message", "source", new DateTime(700))));
		summariesStream1.add(new MessageSummary("2", new Message("message", "source", new DateTime(450))));
		List<MessageSummary> summariesStream2 = new ArrayList<MessageSummary>();
		summariesStream2.add(new MessageSummary("0", new Message("message", "source", new DateTime(100))));
		summariesStream2.add(new MessageSummary("1", new Message("message", "source", new DateTime(200))));
		summariesStream2.add(new MessageSummary("2", new Message("message", "source", new DateTime(300))));
		summariesStream2.add(new MessageSummary("3", new Message("message", "source", new DateTime(400))));
		summariesStream2.add(new MessageSummary("4", new Message("message", "source", new DateTime(500))));
		
		assertEquals(true, correlationCountAlertCondition.checkOrderSecondStream(summariesStream2, summariesStream1));
	}
	
	@Test
	public void testCheckOrderStreamAfterFail() {
		Map<String, Object> parameters = getParametersMap(0,10,CorrelationCount.ThresholdType.MORE,threshold,CorrelationCount.ThresholdType.MORE,0,
				CorrelationCount.OrderType.AFTER.toString());
		final CorrelationCount correlationCountAlertCondition =  getCorrelationCount(parameters, "title");
		 
		List<MessageSummary> summariesStream1 = new ArrayList<MessageSummary>();
		summariesStream1.add(new MessageSummary("0", new Message("message", "source", new DateTime(500))));
		List<MessageSummary> summariesStream2 = new ArrayList<MessageSummary>();
		summariesStream2.add(new MessageSummary("0", new Message("message", "source", new DateTime(100))));
		summariesStream2.add(new MessageSummary("1", new Message("message", "source", new DateTime(200))));
		summariesStream2.add(new MessageSummary("2", new Message("message", "source", new DateTime(300))));
		summariesStream2.add(new MessageSummary("3", new Message("message", "source", new DateTime(400))));
		summariesStream2.add(new MessageSummary("4", new Message("message", "source", new DateTime(600))));
		
		assertEquals(false, correlationCountAlertCondition.checkOrderSecondStream(summariesStream2, summariesStream1));
	}
	
	@Test
	public void testCheckOrderStreamAfterThreshold() {
		Map<String, Object> parameters = getParametersMap(0,10,CorrelationCount.ThresholdType.MORE,threshold,CorrelationCount.ThresholdType.MORE,1,
				CorrelationCount.OrderType.AFTER.toString());
		final CorrelationCount correlationCountAlertCondition =  getCorrelationCount(parameters, "title");
		 
		List<MessageSummary> summariesStream1 = new ArrayList<MessageSummary>();
		summariesStream1.add(new MessageSummary("0", new Message("message", "source", new DateTime(600))));
		summariesStream1.add(new MessageSummary("1", new Message("message", "source", new DateTime(700))));

		List<MessageSummary> summariesStream2 = new ArrayList<MessageSummary>();
		summariesStream2.add(new MessageSummary("0", new Message("message", "source", new DateTime(100))));
		summariesStream2.add(new MessageSummary("1", new Message("message", "source", new DateTime(200))));
		summariesStream2.add(new MessageSummary("2", new Message("message", "source", new DateTime(300))));
		summariesStream2.add(new MessageSummary("3", new Message("message", "source", new DateTime(400))));
		summariesStream2.add(new MessageSummary("4", new Message("message", "source", new DateTime(500))));
		
		assertEquals(true, correlationCountAlertCondition.checkOrderSecondStream(summariesStream2, summariesStream1));
	}
	
	@Test
	public void testCheckOrderStreamAfterThresholdFail() {
		Map<String, Object> parameters = getParametersMap(0,10,CorrelationCount.ThresholdType.MORE,threshold,CorrelationCount.ThresholdType.MORE,1,
				CorrelationCount.OrderType.AFTER.toString());
		final CorrelationCount correlationCountAlertCondition =  getCorrelationCount(parameters, "title");
		 
		List<MessageSummary> summariesStream1 = new ArrayList<MessageSummary>();
		summariesStream1.add(new MessageSummary("0", new Message("message", "source", new DateTime(500))));
		summariesStream1.add(new MessageSummary("1", new Message("message", "source", new DateTime(700))));

		List<MessageSummary> summariesStream2 = new ArrayList<MessageSummary>();
		summariesStream2.add(new MessageSummary("0", new Message("message", "source", new DateTime(100))));
		summariesStream2.add(new MessageSummary("1", new Message("message", "source", new DateTime(200))));
		summariesStream2.add(new MessageSummary("2", new Message("message", "source", new DateTime(300))));
		summariesStream2.add(new MessageSummary("3", new Message("message", "source", new DateTime(400))));
		summariesStream2.add(new MessageSummary("4", new Message("message", "source", new DateTime(600))));
		
		assertEquals(false, correlationCountAlertCondition.checkOrderSecondStream(summariesStream2, summariesStream1));
	}
	
	@Test
	public void testCheckOrderStreamAfterThreshold2Fail() {
		Map<String, Object> parameters = getParametersMap(0,10,CorrelationCount.ThresholdType.MORE,threshold,CorrelationCount.ThresholdType.MORE,1,
				CorrelationCount.OrderType.AFTER.toString());
		final CorrelationCount correlationCountAlertCondition =  getCorrelationCount(parameters, "title");
		 
		List<MessageSummary> summariesStream1 = new ArrayList<MessageSummary>();
		summariesStream1.add(new MessageSummary("0", new Message("message", "source", new DateTime(500))));
		summariesStream1.add(new MessageSummary("1", new Message("message", "source", new DateTime(1100))));

		List<MessageSummary> summariesStream2 = new ArrayList<MessageSummary>();
		summariesStream2.add(new MessageSummary("0", new Message("message", "source", new DateTime(100))));
		summariesStream2.add(new MessageSummary("1", new Message("message", "source", new DateTime(200))));
		summariesStream2.add(new MessageSummary("2", new Message("message", "source", new DateTime(300))));
		summariesStream2.add(new MessageSummary("3", new Message("message", "source", new DateTime(400))));
		summariesStream2.add(new MessageSummary("4", new Message("message", "source", new DateTime(600))));
		summariesStream2.add(new MessageSummary("5", new Message("message", "source", new DateTime(700))));
		summariesStream2.add(new MessageSummary("6", new Message("message", "source", new DateTime(800))));
		summariesStream2.add(new MessageSummary("7", new Message("message", "source", new DateTime(900))));
		summariesStream2.add(new MessageSummary("8", new Message("message", "source", new DateTime(1000))));
		
		assertEquals(false, correlationCountAlertCondition.checkOrderSecondStream(summariesStream2, summariesStream1));
	}
	
	@Test
	public void testCheckOrderStreamThreshold2After() {
		Map<String, Object> parameters = getParametersMap(0,10,CorrelationCount.ThresholdType.MORE,threshold,CorrelationCount.ThresholdType.MORE,1,
				CorrelationCount.OrderType.AFTER.toString());		 
		final CorrelationCount correlationCountAlertCondition =  getCorrelationCount(parameters, "title");
		 
		List<MessageSummary> summariesStream1 = new ArrayList<MessageSummary>();
		summariesStream1.add(new MessageSummary("0", new Message("message", "source", new DateTime(600))));
		summariesStream1.add(new MessageSummary("1", new Message("message", "source", new DateTime(1100))));

		List<MessageSummary> summariesStream2 = new ArrayList<MessageSummary>();
		summariesStream2.add(new MessageSummary("0", new Message("message", "source", new DateTime(100))));
		summariesStream2.add(new MessageSummary("1", new Message("message", "source", new DateTime(200))));
		summariesStream2.add(new MessageSummary("2", new Message("message", "source", new DateTime(300))));
		summariesStream2.add(new MessageSummary("3", new Message("message", "source", new DateTime(400))));
		summariesStream2.add(new MessageSummary("4", new Message("message", "source", new DateTime(500))));
		summariesStream2.add(new MessageSummary("5", new Message("message", "source", new DateTime(700))));
		summariesStream2.add(new MessageSummary("6", new Message("message", "source", new DateTime(800))));
		summariesStream2.add(new MessageSummary("7", new Message("message", "source", new DateTime(900))));
		summariesStream2.add(new MessageSummary("8", new Message("message", "source", new DateTime(1000))));
		
		assertEquals(true, correlationCountAlertCondition.checkOrderSecondStream(summariesStream2, summariesStream1));
	}
	
	private Map<String, Object> getParametersMap(Integer grace, Integer time, CorrelationCount.ThresholdType type, Number threshold,
    		CorrelationCount.ThresholdType additionalStreamType, Number additionalStreamThreshold, String Order) {
        Map<String, Object> parameters = super.getParametersMap(grace, time, threshold);
        parameters.put("main_threshold_type", type.toString());
        parameters.put("additional_stream",REMOTE_STREAM_ID);
        parameters.put("additional_threshold_type", additionalStreamType.toString());
        parameters.put("additional_threshold", additionalStreamThreshold);
        List<String> fields = new ArrayList<>();
        fields.add("user");
        fields.add("ip_src");
        parameters.put("grouping_fields", fields);
        parameters.put("messages_order", Order);
        
        return parameters;
    }
	
	private CorrelationCount getCorrelationCount(Map<String, Object> parameters, String title) {
    	final Stream stream = mock(Stream.class);
    	when(stream.getTitle()).thenReturn("Additional Title");
    	
        return new CorrelationCount(
            searches,
            stream,
			"CONDITIONMOCKID",
	        Tools.nowUTC(),
	        "MOCKUSER",
	        parameters,
	        title);
    }
	
}
