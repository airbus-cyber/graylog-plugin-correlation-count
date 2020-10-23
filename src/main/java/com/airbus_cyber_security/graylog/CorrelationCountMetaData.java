/*
 * graylog-plugin-correlation-count Source Code
 * Copyright (C) 2018-2020 - Airbus CyberSecurity (SAS) - All rights reserved
 *
 * This file is part of the graylog-plugin-correlation-count GPL Source Code.
 *
 * graylog-plugin-correlation-count Source Code is free software:
 * you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this code.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.airbus_cyber_security.graylog;

import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.ServerStatus;
import org.graylog2.plugin.Version;

import java.net.URI;
import java.util.Collections;
import java.util.Set;

/**
 * Implement the PluginMetaData interface here.
 */
public class CorrelationCountMetaData implements PluginMetaData {
    private static final String PLUGIN_PROPERTIES = "com.airbus-cyber-security.graylog.graylog-plugin-correlation-count/graylog-plugin.properties";

    @Override
    public String getUniqueId() {
        return "com.airbus-cyber-security.graylog.CorrelationCountPlugin";
    }

    @Override
    public String getName() {
        return "Correlation Count Alert Condition";
    }

    @Override
    public String getAuthor() {
        return "Airbus CyberSecurity";
    }

    @Override
    public URI getURL() {
        return URI.create("https://www.airbus-cyber-security.com");
    }

    @Override
    public Version getVersion() {
        return Version.fromPluginProperties(getClass(), PLUGIN_PROPERTIES, "version", Version.from(0, 0, 1, "unknown"));
    }

    @Override
    public String getDescription() {
        return "This condition is triggered when there are more or less messages than the threshold.";
    }

    @Override
    public Version getRequiredVersion() {
        return Version.fromPluginProperties(getClass(), PLUGIN_PROPERTIES, "graylog.version", Version.from(3, 2, 0));
    }

    @Override
    public Set<ServerStatus.Capability> getRequiredCapabilities() {
        return Collections.emptySet();
    }
}
