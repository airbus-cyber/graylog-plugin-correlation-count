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
import { useContext } from 'react';
import PropTypes from 'prop-types';

import { Spinner } from 'components/common';
import useFieldTypes from 'views/logic/fieldtypes/useFieldTypes';
import { ALL_MESSAGES_TIMERANGE } from 'views/Constants';
import StreamsContext from 'contexts/StreamsContext';
import CorrelationCountForm from './CorrelationCountForm';


type Props = {
    eventDefinition: {},
    validation: {},
    onChange: () => void
}

const CorrelationCountFormContainer = (props: Props) => {
    const { data: fieldTypes } = useFieldTypes([], ALL_MESSAGES_TIMERANGE);
    const isLoading = !fieldTypes;
    const streams = useContext(StreamsContext);

    if (isLoading) {
        return <Spinner text="Loading Filter & Correlation Count Information..." />;
    }
    return <CorrelationCountForm allFieldTypes={fieldTypes} streams={streams} {...props} />;
}

CorrelationCountFormContainer.propTypes = {
    eventDefinition: PropTypes.object.isRequired,
    validation: PropTypes.object.isRequired,
    onChange: PropTypes.func.isRequired,
    streams: PropTypes.array.isRequired,
    fieldTypes: PropTypes.object.isRequired,
};

export default CorrelationCountFormContainer;