package com.airbus_cyber_security.graylog.events;

import java.util.Collections;
import java.util.Set;

import com.airbus_cyber_security.graylog.events.contentpack.entities.CorrelationCountProcessorConfigEntity;
import com.airbus_cyber_security.graylog.events.processor.correlation.CorrelationCountProcessor;
import com.airbus_cyber_security.graylog.events.processor.correlation.CorrelationCountProcessorParameters;
import com.airbus_cyber_security.graylog.events.processor.correlation.CorrelationCountProcessorConfig;
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
        registerJacksonSubtype(CorrelationCountProcessorConfigEntity.class,
                CorrelationCountProcessorConfigEntity.TYPE_NAME);

        addEventProcessor(CorrelationCountProcessorConfig.TYPE_NAME,
                CorrelationCountProcessor.class,
                CorrelationCountProcessor.Factory.class,
                CorrelationCountProcessorConfig.class,
                CorrelationCountProcessorParameters.class);
    }
}
