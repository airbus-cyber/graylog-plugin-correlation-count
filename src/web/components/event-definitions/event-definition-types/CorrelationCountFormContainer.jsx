import React from 'react';
import createReactClass from 'create-react-class';

import { Spinner } from 'components/common';

import CorrelationCountForm from './CorrelationCountForm';
import StoreProvider from 'injection/StoreProvider';

const FieldsStore = StoreProvider.getStore('Fields');


const CorrelationCountFormContainer = createReactClass({
    getInitialState() {
        return {
            fields: [],
        };
    },

    componentDidMount() {
        this.loadSplitFields();
    },

    loadSplitFields() {
        FieldsStore.loadFields().then((fields) => {
            this.setState({fields: fields});
        });
    },

    render() {
        const { fields } = this.state;

        if (!fields) {
            return <p><Spinner text="Loading Notification information..." /></p>;
        }
        return <CorrelationCountForm {...this.props} fields={fields} />;
    }
})
export default CorrelationCountFormContainer;