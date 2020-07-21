package com.airbus_cyber_security.graylog;

import com.airbus_cyber_security.graylog.events.CorrelationCountModule;
import org.graylog2.plugin.Plugin;
import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.PluginModule;

import java.util.Arrays;
import java.util.Collection;

public class CorrelationCountPlugin implements Plugin {
    @Override
    public PluginMetaData metadata() {
        return new CorrelationCountMetaData();
    }

    @Override
    public Collection<PluginModule> modules () {
        return Arrays.asList(new CorrelationCountModule());
    }
}
