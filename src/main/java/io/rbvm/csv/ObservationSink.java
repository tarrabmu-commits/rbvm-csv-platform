package io.rbvm.csv;

import java.io.IOException;

@FunctionalInterface
public interface ObservationSink {
    void accept(WazuhObservation observation) throws IOException;
}
