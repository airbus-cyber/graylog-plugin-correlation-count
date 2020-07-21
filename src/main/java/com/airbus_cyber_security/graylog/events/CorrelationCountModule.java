package com.airbus_cyber_security.graylog.events;

import java.util.Collections;
import java.util.Set;

import com.airbus_cyber_security.graylog.CorrelationCountProcessor;
import com.airbus_cyber_security.graylog.CorrelationCountProcessorParameters;
import com.airbus_cyber_security.graylog.events.processor.correlation.CorrelationCountProcessorConfig;
import org.graylog.events.processor.EventProcessorEngine;
import org.graylog.events.processor.EventProcessorExecutionMetrics;
import org.graylog2.plugin.PluginConfigBean;
import org.graylog2.plugin.PluginModule;

public class CorrelationCountModule extends PluginModule {
    /**
     * Returns all configuration beans required by this plugin.
     *
     * Implementing this method is optional. The default method returns an empty {@link Set}.
     */
    @Override
    public Set<? extends PluginConfigBean> getConfigBeans() {
        return Collections.emptySet();
    }

    @Override
    protected void configure() {
        /*addAlertCondition(CorrelationCount.class.getCanonicalName(),
        		CorrelationCount.class,
        		CorrelationCount.Factory.class);*/
        bind(EventProcessorEngine.class).asEagerSingleton();
        bind(EventProcessorExecutionMetrics.class).asEagerSingleton();
        addEventProcessor(CorrelationCountProcessorConfig.TYPE_NAME,
                CorrelationCountProcessor.class,
                CorrelationCountProcessor.Factory.class,
                CorrelationCountProcessorConfig.class,
                CorrelationCountProcessorParameters.class);
    }
}
