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

package com.airbus_cyber_security.graylog.events.processor.correlation.checks;

import com.airbus_cyber_security.graylog.events.processor.correlation.CorrelationCountProcessorConfig;
import com.google.common.annotations.VisibleForTesting;
import org.graylog2.plugin.MessageSummary;
import org.joda.time.DateTime;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class CorrelationCountCheck {

    private final Threshold mainStreamThreshold;
    private final Threshold additionalStreamThreshold;
    private final String messagesOrder;

    public CorrelationCountCheck(CorrelationCountProcessorConfig configuration, String messagesOrder) {
        this.mainStreamThreshold = new Threshold(configuration.thresholdType(), configuration.threshold());
        this.additionalStreamThreshold = new Threshold(configuration.additionalThresholdType(), configuration.additionalThreshold());
        this.messagesOrder = messagesOrder;
    }

    public boolean thresholdsAreReached(long mainCount, long additionalCount) {
        return this.mainStreamThreshold.isReached(mainCount) && this.additionalStreamThreshold.isReached(additionalCount);
    }

    private List<DateTime> getListOrderTimestamp(List<MessageSummary> summaries, OrderType messagesOrderType) {
        List<DateTime> listDate = new ArrayList<>();
        for (MessageSummary messageSummary : summaries) {
            listDate.add(messageSummary.getTimestamp());
        }
        Collections.sort(listDate);
        if (messagesOrderType.equals(OrderType.AFTER)) {
            Collections.reverse(listDate);
        }
        return listDate;
    }

    /*
     * Check that the Second Stream is before or after the first stream
     */
    private boolean checkOrderSecondStream(List<MessageSummary> summariesFirstStream, List<MessageSummary> summariesSecondStream) {
        int countFirstStream = summariesFirstStream.size();
        OrderType messagesOrder = OrderType.fromString(this.messagesOrder);
        List<DateTime> listDateFirstStream = getListOrderTimestamp(summariesFirstStream, messagesOrder);
        List<DateTime> listDateSecondStream = getListOrderTimestamp(summariesSecondStream, messagesOrder);

        for (DateTime dateFirstStream: listDateFirstStream) {
            int countSecondStream = 0;
            for (DateTime dateSecondStream: listDateSecondStream) {
                if ((messagesOrder.equals(OrderType.BEFORE) && dateSecondStream.isBefore(dateFirstStream)) ||
                        (messagesOrder.equals(OrderType.AFTER) && dateSecondStream.isAfter(dateFirstStream))) {
                    countSecondStream++;
                } else {
                    break;
                }
            }
            if (thresholdsAreReached(countFirstStream, countSecondStream)) {
                return true;
            }
            countFirstStream--;
        }
        return false;
    }

    public boolean isRuleTriggered(List<MessageSummary> summariesMainStream, List<MessageSummary> summariesAdditionalStream) {
        if (OrderType.fromString(this.messagesOrder).equals(OrderType.ANY)) {
            return true;
        }
        return checkOrderSecondStream(summariesMainStream, summariesAdditionalStream);
    }
}
