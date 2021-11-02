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
import moment from 'moment';
import { TimeUnitInput } from 'components/common';
import { extractDurationAndUnit } from 'components/common/TimeUnitInput';
import { FormGroup, HelpBlock } from 'components/graylog';
import { TIME_UNITS } from 'components/event-definitions/event-definition-types/FilterForm';

class TimeUnitFormGroup extends React.Component {
    static propTypes = {
        value: PropTypes.number.isRequired,
        label: PropTypes.string.isRequired,
        update: PropTypes.func.isRequired,
        errors: PropTypes.array.isRequired
    };

    constructor(props) {
        super(props);

        this.state = extractDurationAndUnit(props.value, TIME_UNITS);
    }

    handleTimeRangeChange = (nextValue, nextUnit) => {
        const durationInMs = moment.duration(lodash.max([nextValue, 1]), nextUnit).asMilliseconds();

        this.setState({
            duration: nextValue,
            unit: nextUnit
        });
        this.props.update(durationInMs);
    };

    render() {
        const { label, errors } = this.props;
        const { duration, unit } = this.state;

        return (
            // note: there is no controlId set because it just doesn't seem to work for this widget
            //       the controlId is suppose to set the "for" attribute on the label and the "id" attribute on the input
            <FormGroup validationState={errors ? 'error' : null}>
                <TimeUnitInput label={label}
                               update={this.handleTimeRangeChange}
                               value={duration}
                               unit={unit}
                               units={TIME_UNITS}
                               clearable
                               required />
                    {errors && (
                        <HelpBlock>{errors[0]}</HelpBlock>
                    )}
            </FormGroup>
        );
    }
}

export default TimeUnitFormGroup;
