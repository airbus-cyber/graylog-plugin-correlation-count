import React from 'react';
import PropTypes from 'prop-types';

class CorrelationCountSummary extends React.Component {
    static propTypes = {
        config: PropTypes.string.isRequired,
        eventDefinition: PropTypes.string.isRequired,
        //notification: PropTypes.object,
        //definitionNotification: PropTypes.object.isRequired,
    };

    /*static defaultProps = {
        notification: {},
    };*/

    render() {
        const { notification } = this.props;
        return (
            <React.Fragment>
                <tr>
                    <td>Title:</td>
                    <td>{eventDefinition.title || 'No additional stream for this notification.'}</td>
                </tr>
                <tr>
                    <td>Stream:</td>
                    <td>{eventDefinition.stream || 'No stream for this notification.'}</td>
                </tr>
                <tr>
                    <td>Additional Stream:</td>
                    <td>{eventDefinition.additional_stream || 'No additional stream for this notification.'}</td>
                </tr>
                <tr>
                    <td>Additional Threshold Type:</td>
                    <td>{eventDefinition.additional_threshold_type || 'No additional threshold type for this notification.'}</td>
                </tr>
                <tr>
                    <td>Additional Threshold:</td>
                    <td>{eventDefinition.additional_threshold}</td>
                </tr>
                <tr>
                    <td>Main Threshold Type:</td>
                    <td>{eventDefinition.main_threshold_type || 'No main threshold type for this notification.'}</td>
                </tr>
                <tr>
                    <td>Main Threshold:</td>
                    <td>{eventDefinition.main_threshold}</td>
                </tr>
                <tr>
                    <td>Time Range:</td>
                    <td>{eventDefinition.time_range}</td>
                </tr>
                <tr>
                    <td>Messages Order:</td>
                    <td>{eventDefinition.messages_order || 'No messages order for this notification.'}</td>
                </tr>
                <tr>
                    <td>Grace Period:</td>
                    <td>{eventDefinition.grace_period}</td>
                </tr>
                <tr>
                    <td>Message Backlog:</td>
                    <td>{eventDefinition.message_backlog}</td>
                </tr>
                <tr>
                    <td>Grouping Fields:</td>
                    <td>{eventDefinition.grouping_fields.join(', ') || 'No grouping fields for this notification.'}</td>
                </tr>
                <tr>
                    <td>Comment:</td>
                    <td>{eventDefinition.comment}</td>
                </tr>
                <tr>
                    <td>Search Query:</td>
                    <td>{eventDefinition.search_query}</td>
                </tr>
            </React.Fragment>
        );
    }
}

export default CorrelationCountSummary;