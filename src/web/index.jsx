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
              time_range: '5',
              messages_order: 'any order',
              grace_period: '0',
              message_backlog: '0',
              grouping_fields: [],
              comment: '',
              search_query: '*',
              repeat_notifications: false,
            },
        },
    ],
}));