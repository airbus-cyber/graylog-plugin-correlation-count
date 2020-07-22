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
        const { errors } = this.props;
        const { duration, unit } = this.state;

        return (
            // TODO controlId should be a props
            <FormGroup controlId="search-within" validationState={errors ? 'error' : null}>
                <TimeUnitInput label="Search within the last"
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
