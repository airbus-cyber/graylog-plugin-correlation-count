package com.airbus_cyber_security.graylog;

import java.util.Collections;
import java.util.Set;

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
    	
        addAlertCondition(CorrelationCount.class.getCanonicalName(),
        		CorrelationCount.class,
        		CorrelationCount.Factory.class);
    }
}
