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

import React from 'react';
import PropTypes from 'prop-types';
import lodash from 'lodash';
import FormsUtils from 'util/FormsUtils';
import { naturalSortIgnoreCase } from 'util/SortUtils';

import { Select, MultiSelect } from 'components/common';
// TODO write a unit test which protects against having ControlLable, FormGroup and HelpBlock imported from components/common
import { ControlLabel, FormGroup, HelpBlock, Input } from 'components/bootstrap';
import TimeUnitFormGroup from './TimeUnitFormGroup';

import { defaultCompare } from 'logic/DefaultCompare';


class CorrelationCountForm extends React.Component {
    // Memoize function to only format fields when they change. Use joined fieldNames as cache key.
    formatFields = lodash.memoize(
        (fieldTypes) => {
            return fieldTypes
                .sort((ftA, ftB) => defaultCompare(ftA.name, ftB.name))
                .map((fieldType) => {
                    return {
                        label: `${fieldType.name} – ${fieldType.value.type.type}`,
                        value: fieldType.name,
                    };
                }
            );
        },
        (fieldTypes) => fieldTypes.map((ft) => ft.name).join('-'),
    );

    static propTypes = {
        eventDefinition: PropTypes.object.isRequired,
        validation: PropTypes.object.isRequired,
        onChange: PropTypes.func.isRequired,
        streams: PropTypes.array.isRequired,
        allFieldTypes: PropTypes.array.isRequired,
    };

    formatStreamIds = () => {
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
    };

    propagateChange = (key, value) => {
        const { eventDefinition, onChange } = this.props;
        const config = lodash.cloneDeep(eventDefinition.config);
        config[key] = value;
        onChange('config', config);
    };

    handleChange = (event) => {
        const { name } = event.target;
        this.propagateChange(name, FormsUtils.getValueFromInput(event.target));
    };

    handleSearchWithinMsChange = (nextValue) => {
        this.propagateChange('search_within_ms', nextValue);
    };

    handleExecuteEveryMsChange = (nextValue) => {
        this.propagateChange('execute_every_ms', nextValue);
    };

    handleStreamChange = (nextValue) => {
        this.propagateChange('stream', nextValue);
    };

    handleAdditionalStreamChange = (nextValue) => {
        this.propagateChange('additional_stream', nextValue);
    };

    handleAdditionalThresholdTypeChange = (nextValue) => {
        this.propagateChange('additional_threshold_type', nextValue);
    };

    handleThresholdTypeChange = (nextValue) => {
        this.propagateChange('threshold_type', nextValue);
    };

    handleMessagesOrderChange = (nextValue) => {
        this.propagateChange('messages_order', nextValue);
    };

    handleGroupByChange = (selected) => {
        const nextValue = selected === '' ? [] : selected.split(',');
        this.propagateChange('grouping_fields', nextValue)
    };

    availableThresholdTypes = () => {
        return [
            {value: 'MORE', label: 'more than'},
            {value: 'LESS', label: 'less than'},
        ];
    };

    availableMessagesOrder = () => {
        return [
            {value: 'BEFORE', label: 'additional messages before main messages'},
            {value: 'AFTER', label: 'additional messages after main messages'},
            {value: 'ANY', label: 'any order'},
        ]
    };

    render() {
        const { eventDefinition, validation, allFieldTypes } = this.props;
        const formattedStreams = this.formatStreamIds();
        const formattedFields = this.formatFields(allFieldTypes);

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
                    label="Search within the last"
                    value={lodash.defaultTo(eventDefinition.search_within_ms, eventDefinition.config.search_within_ms)}
                    update={this.handleSearchWithinMsChange}
                    errors={validation.errors.search_within_ms}
                />
                <TimeUnitFormGroup
                    label="Execute search every"
                    value={lodash.defaultTo(eventDefinition.execute_every_ms, eventDefinition.config.execute_every_ms)}
                    update={this.handleExecuteEveryMsChange}
                    errors={validation.errors.execute_every_ms}
                />
                <FormGroup controlId="group-by">
                    <ControlLabel>Group by Field(s) <small className="text-muted">(Optional)</small></ControlLabel>
                    <MultiSelect id="group-by"
                                 matchProp="label"
                                 onChange={this.handleGroupByChange}
                                 options={formattedFields}
                                 ignoreAccents={false}
                                 value={lodash.defaultTo(eventDefinition.config.grouping_fields, []).join(',')}
                                 allowCreate />
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
            </React.Fragment>
        );
    }
}

export default CorrelationCountForm;
