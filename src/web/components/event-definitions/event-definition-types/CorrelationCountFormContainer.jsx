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

import { Spinner } from 'components/common';

import connect from 'stores/connect';
import withStreams from 'components/event-definitions/event-definition-types/withStreams';

import CorrelationCountForm from './CorrelationCountForm';
import { FieldTypesStore } from 'views/stores/FieldTypesStore';
import StoreProvider from 'injection/StoreProvider';

import CombinedProvider from 'injection/CombinedProvider';

const { StreamsStore } = CombinedProvider.get('Streams');

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

    render() {
        const { fieldTypes, ...otherProps } = this.props;

        const isLoading = typeof fieldTypes.all !== 'object';

        if (isLoading) {
            return <Spinner text="Loading Filter & Correlation Count Information..." />;
        }
        return <CorrelationCountForm allFieldTypes={fieldTypes.all.toJS()} {...otherProps} />;
    }
}

export default connect(withStreams(CorrelationCountFormContainer, HIDDEN_STREAMS), {
    fieldTypes: FieldTypesStore,
});