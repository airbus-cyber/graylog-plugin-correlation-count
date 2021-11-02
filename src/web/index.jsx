/*
 * Copyright (C) 2018 Airbus CyberSecurity (SAS)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
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