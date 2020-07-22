import React from 'react';
import createReactClass from 'create-react-class';
import PropTypes from 'prop-types';
import lodash from 'lodash';
import FormsUtils from 'util/FormsUtils';
import naturalSort from 'javascript-natural-sort';
import { naturalSortIgnoreCase } from 'util/SortUtils';

import { ControlLabel, FormGroup, HelpBlock } from 'components/graylog';
import { Select, MultiSelect } from 'components/common';
import { Input } from 'components/bootstrap';
import TimeUnitFormGroup from './TimeUnitFormGroup';


const CorrelationCountForm = createReactClass({

    propTypes: {
        eventDefinition: PropTypes.object.isRequired,
        validation: PropTypes.object.isRequired,
        onChange: PropTypes.func.isRequired,
        streams: PropTypes.array.isRequired,
        fields: PropTypes.array.isRequired,
    },

    formatStreamIds() {
        const { streams } = this.props;

        return streams.map(s => s.id)
            .map(streamId => streams.find(s => s.id === streamId) || streamId)
            .map((streamOrId) => {
                const stream = (typeof streamOrId === 'object' ? streamOrId : { title: streamOrId, id: streamOrId });
                return {
                    label: stream.title,
                    value: stream.id,
                };
            })
            .sort((s1, s2) => naturalSortIgnoreCase(s1.label, s2.label));
    },

    propagateChange(key, value) {
        const { eventDefinition, onChange } = this.props;
        const config = lodash.cloneDeep(eventDefinition.config);
        config[key] = value;
        onChange('config', config);
    },

    handleChange(event) {
        const { name } = event.target;
        this.propagateChange(name, FormsUtils.getValueFromInput(event.target));
    },

    handleSearchWithinMsChange(nextValue) {
        this.propagateChange('search_within_ms', nextValue);
    },

    handleStreamChange(nextValue) {
        this.propagateChange('stream', nextValue);
    },

    handleAdditionalStreamChange(nextValue) {
        this.propagateChange('additional_stream', nextValue);
    },

    handleAdditionalThresholdTypeChange(nextValue) {
        this.propagateChange('additional_threshold_type', nextValue);
    },

    handleThresholdTypeChange(nextValue) {
        this.propagateChange('threshold_type', nextValue);
    },

    handleMessagesOrderChange(nextValue) {
        this.propagateChange('messages_order', nextValue);
    },

    handleFieldsChange(key) {
        return nextValue => {
            this.propagateChange(key, nextValue === '' ? [] : nextValue.split(','));
        }
    },

    availableThresholdTypes() {
        return [
            {value: 'MORE', label: 'more than'},
            {value: 'LESS', label: 'less than'},
        ];
    },

    availableMessagesOrder() {
        return [
            {value: 'BEFORE', label: 'additional messages before main messages'},
            {value: 'AFTER', label: 'additional messages after main messages'},
            {value: 'ANY', label: 'any order'},
        ]
    },

    _formatOption(key, value) {
        return {value: value, label: key};
    },

    render() {
        const { eventDefinition, validation, fields } = this.props;

        const formattedStreams = this.formatStreamIds();

        let formattedOptions = null;
        if(fields) {
            formattedOptions = Object.keys(fields).map(key => this._formatOption(fields[key], fields[key]))
                .sort((s1, s2) => naturalSort(s1.label.toLowerCase(), s2.label.toLowerCase()));
        }
        return (
            <React.Fragment>
                <FormGroup controlId="stream"
                           validationState={validation.errors.stream ? 'error' : null}>
                    <ControlLabel>Stream</ControlLabel>
                    <Select id="stream"
                            placeholder="Select Stream"
                            required
                            options={formattedStreams}
                            matchProp="value"
                            value={lodash.defaultTo(eventDefinition.stream, eventDefinition.config.stream)}
                            onChange={this.handleStreamChange}
                    />
                    <HelpBlock>
                        Select streams the search should include. Searches in all streams if empty.
                    </HelpBlock>
                </FormGroup>
                <FormGroup controlId="threshold_type"
                           validationState={validation.errors.threshold_type ? 'error' : null}>
                    <ControlLabel>Threshold Type</ControlLabel>
                    <Select id="threshold_type"
                            required
                            options={this.availableThresholdTypes()}
                            matchProp="value"
                            value={lodash.defaultTo(eventDefinition.threshold_type, eventDefinition.config.threshold_type)}
                            onChange={this.handleThresholdTypeChange}
                    />
                    <HelpBlock>
                        Select condition to trigger alert: when there are more or less messages in the main stream than the threshold
                    </HelpBlock>
                </FormGroup>
                <ControlLabel>Threshold</ControlLabel>
                <Input
                    id="threshold"
                    type="number"
                    name="threshold"
                    help="Value which triggers an alert if crossed"
                    value={lodash.defaultTo(eventDefinition.threshold, eventDefinition.config.threshold)}
                    onChange={this.handleChange}
                />
                <FormGroup controlId="additional_stream"
                           validationState={validation.errors.additional_stream ? 'error' : null}>
                    <ControlLabel>Additional Stream</ControlLabel>
                    <Select id="additional_stream"
                            placeholder="Select Additional Stream"
                            required
                            options={formattedStreams}
                            matchProp="value"
                            value={lodash.defaultTo(eventDefinition.additional_stream, eventDefinition.config.additional_stream)}
                            onChange={this.handleAdditionalStreamChange}
                    />
                    <HelpBlock>
                        Select the stream to correlate with the main stream
                    </HelpBlock>
                </FormGroup>
                <FormGroup controlId="additional_threshold_type"
                           validationState={validation.errors.additional_threshold_type ? 'error' : null}>
                    <ControlLabel>Additional Threshold Type</ControlLabel>
                    <Select id="additional_threshold_type"
                            required
                            options={this.availableThresholdTypes()}
                            matchProp="value"
                            value={lodash.defaultTo(eventDefinition.additional_threshold_type, eventDefinition.config.additional_threshold_type)}
                            onChange={this.handleAdditionalThresholdTypeChange}
                    />
                    <HelpBlock>
                        Select condition to trigger alert: when there are more or less messages in the additional stream than the threshold
                    </HelpBlock>
                </FormGroup>
                <ControlLabel>Additional Threshold</ControlLabel>
                <Input
                    id="additional_threshold"
                    type="number"
                    name="additional_threshold"
                    help="Value which triggers an alert if crossed"
                    value={lodash.defaultTo(eventDefinition.additional_threshold, eventDefinition.config.additional_threshold)}
                    onChange={this.handleChange}
                />
                <FormGroup controlId="messages_order"
                           validationState={validation.errors.messages_order ? 'error' : null}>
                    <ControlLabel>Messages Order</ControlLabel>
                    <Select id="messages_order"
                            required
                            options={this.availableMessagesOrder()}
                            matchProp="value"
                            value={lodash.defaultTo(eventDefinition.messages_order, eventDefinition.config.messages_order)}
                            onChange={this.handleMessagesOrderChange}
                    />
                    <HelpBlock>
                        Select condition to trigger alert: when the messages of the additional stream come in any order relative to/before/after the messages of the main stream
                    </HelpBlock>
                </FormGroup>
                <TimeUnitFormGroup
                    value={lodash.defaultTo(eventDefinition.search_within_ms, eventDefinition.config.search_within_ms)}
                    update={this.handleSearchWithinMsChange}
                    errors={validation.errors.search_within_ms}
                />
                <ControlLabel>Time Range</ControlLabel>
                <Input
                    id="time_range"
                    type="number"
                    name="time_range"
                    help="Evaluate the condition for all messages received in the given number of minutes"
                    value={lodash.defaultTo(eventDefinition.time_range, eventDefinition.config.time_range)}
                    onChange={this.handleChange}
                />
                <ControlLabel>Grace Period</ControlLabel>
                <Input
                    id="grace_period"
                    type="number"
                    name="grace_period"
                    help="Number of minutes to wait after an alert is resolved, to trigger another alert"
                    value={lodash.defaultTo(eventDefinition.grace_period, eventDefinition.config.grace_period)}
                    onChange={this.handleChange}
                />
                <ControlLabel>Message Backlog</ControlLabel>
                <Input
                    id="message_backlog"
                    type="number"
                    name="message_backlog"
                    help="The number of message to be included in alert notifications"
                    value={lodash.defaultTo(eventDefinition.message_backlog, eventDefinition.config.message_backlog)}
                    onChange={this.handleChange}
                />
                <FormGroup controlId="grouping_fields">
                    <ControlLabel>Grouping Fields <small className="text-muted">(Optional)</small></ControlLabel>
                    <MultiSelect id="grouping_fields"
                                 placeholder="Add Grouping Fields"
                                 required
                                 options={formattedOptions}
                                 matchProp="value"
                                 value={Array.isArray(lodash.defaultTo(eventDefinition.grouping_fields)) ? lodash.defaultTo(eventDefinition.grouping_fields).join(',') : eventDefinition.config.grouping_fields.join(',')}
                                 onChange={this.handleFieldsChange('grouping_fields')}
                    />
                    <HelpBlock>
                        Fields that should be checked to count messages with the same values
                    </HelpBlock>
                </FormGroup>
                <ControlLabel>Comment <small className="text-muted">(Optional)</small></ControlLabel>
                <Input
                    id="comment"
                    type="text"
                    name="comment"
                    help="Comment about the configuration"
                    value={lodash.defaultTo(eventDefinition.comment, eventDefinition.config.comment)}
                    onChange={this.handleChange}
                />
                <ControlLabel>Search Query <small className="text-muted">(Optional)</small></ControlLabel>
                <Input
                    id="search_query"
                    type="text"
                    name="search_query"
                    help="Query string that should be used to filter messages in the stream"
                    value={lodash.defaultTo(eventDefinition.search_query, eventDefinition.config.search_query)}
                    onChange={this.handleChange}
                />
                <div>
                    <Input
                        id="repeat_notifications"
                        type="checkbox"
                        name="repeat_notifications"
                        checked={eventDefinition.config.repeat_notifications}
                        onChange={this.handleChange}
                        style={{position: 'absolute'}}
                    />
                    <label style={{padding: '10px 20px'}}>Repeat notifications <small className='text-muted'>(Optional)</small></label>
                    <HelpBlock>
                        Check this box to send notifications every time the alert condition is evaluated and satisfied regardless of its state
                    </HelpBlock>
                </div>
            </React.Fragment>
        );
    },

});

export default CorrelationCountForm;