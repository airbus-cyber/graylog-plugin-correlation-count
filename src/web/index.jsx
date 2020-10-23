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

import { PluginManifest, PluginStore } from 'graylog-web-plugin/plugin';

import CorrelationCountFormContainer from "./components/event-definitions/event-definition-types/CorrelationCountFormContainer";
import CorrelationCountSummary from "./components/event-definitions/event-definition-types/CorrelationCountSummary";

PluginStore.register(new PluginManifest({}, {
    eventDefinitionTypes: [
        {
            type: 'correlation-count',
            displayName: 'Correlation Count Alert Condition',
            sortOrder: 1, // Sort before conditions working on events
            description: 'This condition is triggered when the number of messages in the main stream is higher/lower than a defined '
                + 'threshold and when the number of messages in the additional stream is higher/lower than another defined ' +
                'threshold in a given time range.',
            formComponent: CorrelationCountFormContainer,
            summaryComponent: CorrelationCountSummary,
            defaultConfig: {
              stream: '',
              threshold_type: 'more than',
              threshold: '0',
              additional_stream: '',
              additional_threshold_type: 'more than',
              additional_threshold: '0',
              search_within_ms: 60*1000,
              execute_every_ms: 60*1000,
              messages_order: 'any order',
              grouping_fields: [],
              comment: '',
              search_query: '*',
            },
        },
    ],
}));