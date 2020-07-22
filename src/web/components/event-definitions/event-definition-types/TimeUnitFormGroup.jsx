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

        const searchWithin = extractDurationAndUnit(props.value, TIME_UNITS);

        // TODO maybe, could simply do this.state = searchWithin?
        this.state = {
          searchWithinMsDuration: searchWithin.duration,
          searchWithinMsUnit: searchWithin.unit,
        };
    }

    handleTimeRangeChange = (nextValue, nextUnit) => {
        const durationInMs = moment.duration(lodash.max([nextValue, 1]), nextUnit).asMilliseconds();

        this.setState({
            // TODO should use generic names here duration and unit
            searchWithinMsDuration: nextValue,
            searchWithinMsUnit: nextUnit
        });
        this.props.update(durationInMs);
    };

    render() {
        const { errors } = this.props;
        const { searchWithinMsDuration, searchWithinMsUnit } = this.state;

        return (
            // TODO controlId should be a props
            <FormGroup controlId="search-within" validationState={errors ? 'error' : null}>
                <TimeUnitInput label="Search within the last"
                               update={this.handleTimeRangeChange}
                               value={searchWithinMsDuration}
                               unit={searchWithinMsUnit}
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
