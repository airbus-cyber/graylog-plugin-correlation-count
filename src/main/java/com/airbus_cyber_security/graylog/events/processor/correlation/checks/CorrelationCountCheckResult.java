package com.airbus_cyber_security.graylog.events.processor.correlation.checks;

import org.graylog2.plugin.MessageSummary;

import java.util.List;

public class CorrelationCountCheckResult {

    private String resultDescription;

    private List<MessageSummary> messageSummaries;

    public CorrelationCountCheckResult(final String resultDescription, final List<MessageSummary> messageSummaries) {
        this.resultDescription = resultDescription;
        this.messageSummaries = messageSummaries;
    }

    public String getResultDescription() {
        return resultDescription;
    }

    public void setResultDescription(String resultDescription) {
        this.resultDescription = resultDescription;
    }

    public List<MessageSummary> getMessageSummaries() {
        return messageSummaries;
    }

    public void setMessageSummaries(List<MessageSummary> messageSummaries) {
        this.messageSummaries = messageSummaries;
    }
}
