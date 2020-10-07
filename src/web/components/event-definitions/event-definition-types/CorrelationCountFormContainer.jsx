import React from 'react';

import { Spinner } from 'components/common';

import connect from 'stores/connect';
import withStreams from 'components/event-definitions/event-definition-types/withStreams';

import CorrelationCountForm from './CorrelationCountForm';
import StoreProvider from 'injection/StoreProvider';

import CombinedProvider from 'injection/CombinedProvider';

const { StreamsStore } = CombinedProvider.get('Streams');

const FieldsStore = StoreProvider.getStore('Fields');

// We currently don't support creating Events from these Streams, since they also contain Events
// and it's not possible to access custom Fields defined in them.
const HIDDEN_STREAMS = [
    '000000000000000000000002',
    '000000000000000000000003',
];

class CorrelationCountFormContainer extends React.Component {
    static propTypes = {
        eventDefinition: PropTypes.object.isRequired,
        validation: PropTypes.object.isRequired,
        onChange: PropTypes.func.isRequired,
        streams: PropTypes.array.isRequired,
        fieldTypes: PropTypes.object.isRequired,
    };

    getInitialState = () => {
        return {
            fields: [],
        };
    };

    componentDidMount = () => {
        this.loadSplitFields();
    };

    loadSplitFields = () => {
        FieldsStore.loadFields().then((fields) => {
            this.setState({fields: fields});
        });
    };

    render() {
        const { fields } = this.state;

        if (!fields) {
            return <p><Spinner text="Loading Notification information..." /></p>;
        }
        return <CorrelationCountForm {...this.props} fields={fields} />;
    }
}

export default connect(withStreams(CorrelationCountFormContainer, HIDDEN_STREAMS), {});