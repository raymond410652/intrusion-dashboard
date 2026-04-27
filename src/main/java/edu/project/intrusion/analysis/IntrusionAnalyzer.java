package edu.project.intrusion.analysis;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

import edu.project.intrusion.model.Alert;
import edu.project.intrusion.model.AnalysisResult;
import edu.project.intrusion.model.LogEntry;

public class IntrusionAnalyzer {

    public AnalysisResult analyze(List<LogEntry> entries) {
        ExecutorService executor = Executors.newFixedThreadPool(3);

        try {
            Future<List<Alert>> failedLoginFuture = executor.submit(createFailedLoginTask(entries));
            Future<List<Alert>> portScanFuture = executor.submit(createPortScanTask(entries));
            Future<List<Alert>> trafficSpikeFuture = executor.submit(createTrafficSpikeTask(entries));

            List<Alert> allAlerts = new ArrayList<>();
            allAlerts.addAll(failedLoginFuture.get());
            allAlerts.addAll(portScanFuture.get());
            allAlerts.addAll(trafficSpikeFuture.get());

            int failedLoginIps = (int) allAlerts.stream()
                    .filter(a -> a.type().equals("FAILED_LOGIN"))
                    .map(Alert::sourceIp)
                    .distinct()
                    .count();

            int portScanIps = (int) allAlerts.stream()
                    .filter(a -> a.type().equals("PORT_SCAN"))
                    .map(Alert::sourceIp)
                    .distinct()
                    .count();

            int trafficSpikeMinutes = (int) allAlerts.stream()
                    .filter(a -> a.type().equals("TRAFFIC_SPIKE"))
                    .count();

            Map<String, Integer> topSourceIps = entries.stream()
                    .collect(Collectors.groupingBy(LogEntry::sourceIp, Collectors.summingInt(e -> 1)))
                    .entrySet()
                    .stream()
                    .sorted(Map.Entry.<String, Integer>comparingByValue(Comparator.reverseOrder()))
                    .limit(5)
                    .collect(Collectors.toMap(
                            Map.Entry::getKey,
                            Map.Entry::getValue,
                            (a, b) -> a,
                            LinkedHashMap::new
                    ));

            return new AnalysisResult(
                    entries.size(),
                    failedLoginIps,
                    portScanIps,
                    trafficSpikeMinutes,
                    allAlerts,
                    topSourceIps
            );

        } catch (InterruptedException | ExecutionException e) {
            throw new RuntimeException("Analysis failed", e);
        } finally {
            executor.shutdown();
        }
    }

    private Callable<List<Alert>> createFailedLoginTask(List<LogEntry> entries) {
        return () -> {
            Map<String, Integer> failedCounts = new HashMap<>();

            for (LogEntry entry : entries) {
                if (entry.statusCode() >= 400) {
                    failedCounts.merge(entry.sourceIp(), 1, Integer::sum);
                }
            }

            List<Alert> alerts = new ArrayList<>();
            for (Map.Entry<String, Integer> entry : failedCounts.entrySet()) {
                if (entry.getValue() >= 5) {
                    alerts.add(new Alert(
                            "FAILED_LOGIN",
                            "HIGH",
                            "Repeated failed logins detected from IP " + entry.getKey()
                                    + " (" + entry.getValue() + " failures)",
                            entry.getKey()
                    ));
                }
            }
            return alerts;
        };
    }

    private Callable<List<Alert>> createPortScanTask(List<LogEntry> entries) {
        return () -> {
            Map<String, Set<Integer>> portsByIp = new HashMap<>();

            for (LogEntry entry : entries) {
                portsByIp
                        .computeIfAbsent(entry.sourceIp(), k -> new HashSet<>())
                        .add(entry.destinationPort());
            }

            List<Alert> alerts = new ArrayList<>();
            for (Map.Entry<String, Set<Integer>> entry : portsByIp.entrySet()) {
                if (entry.getValue().size() >= 10) {
                    alerts.add(new Alert(
                            "PORT_SCAN",
                            "HIGH",
                            "Possible port scan from IP " + entry.getKey()
                                    + " targeting " + entry.getValue().size() + " ports",
                            entry.getKey()
                    ));
                }
            }
            return alerts;
        };
    }

    private Callable<List<Alert>> createTrafficSpikeTask(List<LogEntry> entries) {
        return () -> {
            Map<String, Integer> countPerMinute = new HashMap<>();

            for (LogEntry entry : entries) {
                String minuteKey = entry.timestamp().length() >= 16
                        ? entry.timestamp().substring(0, 16)
                        : entry.timestamp();

                countPerMinute.merge(minuteKey, 1, Integer::sum);
            }

            List<Alert> alerts = new ArrayList<>();
            for (Map.Entry<String, Integer> entry : countPerMinute.entrySet()) {
                if (entry.getValue() >= 20) {
                    alerts.add(new Alert(
                            "TRAFFIC_SPIKE",
                            "MEDIUM",
                            "Traffic spike detected at minute " + entry.getKey()
                                    + " with " + entry.getValue() + " events",
                            "N/A"
                    ));
                }
            }
            return alerts;
        };
    }
}