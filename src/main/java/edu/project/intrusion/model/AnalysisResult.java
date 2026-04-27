package edu.project.intrusion.model;

import java.io.Serializable;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public record AnalysisResult(
        int totalRecords,
        int failedLoginIps,
        int portScanIps,
        int trafficSpikeMinutes,
        List<Alert> alerts,
        Map<String, Integer> topSourceIps
) implements Serializable {
    private static final long serialVersionUID = 1L;

    public AnalysisResult {
        totalRecords = Math.max(totalRecords, 0);
        failedLoginIps = Math.max(failedLoginIps, 0);
        portScanIps = Math.max(portScanIps, 0);
        trafficSpikeMinutes = Math.max(trafficSpikeMinutes, 0);
        alerts = List.copyOf(alerts == null ? List.of() : alerts);
        topSourceIps = Collections.unmodifiableMap(
                new LinkedHashMap<>(topSourceIps == null ? Map.of() : topSourceIps)
        );
    }
}
