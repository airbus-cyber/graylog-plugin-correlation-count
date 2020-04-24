package com.airbus_cyber_security.graylog;

import com.airbus_cyber_security.graylog.config.CorrelationCountProcessorConfig;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;
import org.graylog.events.processor.EventProcessorParametersWithTimerange;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.graylog2.plugin.indexer.searches.timeranges.InvalidRangeParametersException;
import org.graylog2.plugin.indexer.searches.timeranges.RelativeRange;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
import org.joda.time.DateTime;

import static com.google.common.base.Preconditions.checkArgument;
import static java.util.Objects.requireNonNull;

@AutoValue
@JsonTypeName(CorrelationCountProcessorConfig.TYPE_NAME)
@JsonDeserialize(builder = CorrelationCountProcessorParameters.Builder.class)
public abstract class CorrelationCountProcessorParameters implements EventProcessorParametersWithTimerange {
    @Override
    public EventProcessorParametersWithTimerange withTimerange(DateTime from, DateTime to) {
        requireNonNull(from, "from cannot be null");
        requireNonNull(to, "to cannot be null");
        checkArgument(to.isAfter(from), "to must be after from");

        return toBuilder().timerange(AbsoluteRange.create(from, to)).build();
    }

    public abstract Builder toBuilder();

    public static Builder builder() {
        return Builder.create();
    }

    @AutoValue.Builder
    public static abstract class Builder implements EventProcessorParametersWithTimerange.Builder<Builder> {
        @JsonCreator
        public static Builder create() {
            final RelativeRange timerange;
            try {
                timerange = RelativeRange.create(3600);
            } catch (InvalidRangeParametersException e) {
                // This should not happen!
                throw new RuntimeException(e);
            }

            return new AutoValue_CorrelationCountProcessorParameters.Builder()
                    .type(CorrelationCountProcessorConfig.TYPE_NAME)
                    .timerange(timerange);
        }

        public abstract CorrelationCountProcessorParameters build();
    }
}
