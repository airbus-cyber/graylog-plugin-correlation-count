import React from 'react';
import PropTypes from 'prop-types';
import { extractDurationAndUnit } from 'components/common/TimeUnitInput';
import { TIME_UNITS } from 'components/event-definitions/event-definition-types/FilterForm';

class CorrelationCountSummary extends React.Component {
    static propTypes = {
        config: PropTypes.string.isRequired,
    };

    render() {
        const { config } = this.props;
        const searchWithin = extractDurationAndUnit(config.search_within_ms, TIME_UNITS);
        const executeEvery = extractDurationAndUnit(config.execute_every_ms, TIME_UNITS);

        return (
            <React.Fragment>
                <tr>
                    <td>Stream:</td>
                    <td>{config.stream || 'No stream for this condition.'}</td>
                </tr>
                <tr>
                    <td>Threshold Type:</td>
                    <td>{config.threshold_type || 'No threshold type for this condition.'}</td>
                </tr>
                <tr>
                    <td>Threshold:</td>
                    <td>{config.threshold}</td>
                </tr>
                <tr>
                    <td>Additional Stream:</td>
                    <td>{config.additional_stream || 'No additional stream for this condition.'}</td>
                </tr>
                <tr>
                    <td>Additional Threshold Type:</td>
                    <td>{config.additional_threshold_type || 'No additional threshold type for this condition.'}</td>
                </tr>
                <tr>
                    <td>Additional Threshold:</td>
                    <td>{config.additional_threshold}</td>
                </tr>
                <tr>
                    <td>Messages Order:</td>
                    <td>{config.messages_order || 'No messages order for this condition.'}</td>
                </tr>
                <tr>
                    <td>Search within:</td>
                    <td>{searchWithin.duration} {searchWithin.unit.toLowerCase()}</td>
                </tr>
                <tr>
                    <td>Execute search every:</td>
                    <td>{executeEvery.duration} {executeEvery.unit.toLowerCase()}</td>
                </tr>
                <tr>
                    <td>Grouping Fields:</td>
                    <td>{config.grouping_fields.join(', ') || 'No grouping fields for this condition.'}</td>
                </tr>
                <tr>
                    <td>Comment:</td>
                    <td>{config.comment}</td>
                </tr>
                <tr>
                    <td>Search Query:</td>
                    <td>{config.search_query}</td>
                </tr>
            </React.Fragment>
        );
    }
}

export default CorrelationCountSummary;