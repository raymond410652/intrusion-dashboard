package edu.project.intrusion.server;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import edu.project.intrusion.analysis.IntrusionAnalyzer;
import edu.project.intrusion.db.DatabaseManager;
import edu.project.intrusion.model.AnalysisResult;
import edu.project.intrusion.model.LogEntry;
import edu.project.intrusion.net.AnalyzeRequest;
import edu.project.intrusion.net.AnalyzeResponse;
import edu.project.intrusion.net.HistoryRequest;
import edu.project.intrusion.net.HistoryResponse;
import edu.project.intrusion.parser.CsvLogParser;

public class LogAnalysisServer {

    private static final int PORT = 5060;
    private static final int MAX_CLIENTS = 10;
    private static final AtomicInteger DASHBOARD_COUNTER = new AtomicInteger(1);
    private static final Map<String, Integer> DASHBOARD_CLIENT_NUMBERS = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        DatabaseManager.initDatabase();
        if (!DatabaseManager.canConnect()) {
            throw new IllegalStateException("Unable to connect to the analysis database.");
        }

        ExecutorService pool = Executors.newFixedThreadPool(MAX_CLIENTS, createThreadFactory());

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Log Analysis Server started on port " + PORT);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                pool.submit(() -> handleClient(clientSocket));
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void handleClient(Socket socket) {
        try (socket;
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            out.flush();
            Object requestObject = null;
            try {
                requestObject = in.readObject();
                String dashboardLabel = resolveDashboardLabel(requestObject);
                if (requestObject instanceof AnalyzeRequest request) {
                    System.out.println(dashboardLabel + " -> ANALYZE " + request.fileName());
                    handleAnalyzeRequest(request, out);
                } else if (requestObject instanceof HistoryRequest request) {
                    System.out.println(dashboardLabel + " -> " + describeHistoryRequest(request));
                    handleHistoryRequest(request, out);
                } else {
                    System.out.println("unknown-dashboard -> INVALID REQUEST " + requestObject);
                    out.writeObject(new AnalyzeResponse(false, "Invalid request type", null));
                }
                out.flush();
            } catch (Exception e) {
                System.out.println("Server request failed: " + e.getMessage());
                e.printStackTrace();
                if (requestObject instanceof AnalyzeRequest) {
                    out.writeObject(new AnalyzeResponse(false, "Server error: " + e.getMessage(), null));
                } else {
                    out.writeObject(HistoryResponse.failure("Server error: " + e.getMessage()));
                }
                out.flush();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void handleAnalyzeRequest(AnalyzeRequest request, ObjectOutputStream out) throws Exception {
        CsvLogParser parser = new CsvLogParser();
        List<LogEntry> entries = parser.parse(request.csvContent());

        IntrusionAnalyzer analyzer = new IntrusionAnalyzer();
        AnalysisResult result = analyzer.analyze(entries);

        long jobId = DatabaseManager.saveAnalysis(request.fileName(), entries, result);

        out.writeObject(new AnalyzeResponse(true, "Analysis completed successfully", result));
        System.out.println("Processed file: " + request.fileName() + " as database job " + jobId);
    }

    private static void handleHistoryRequest(HistoryRequest request, ObjectOutputStream out) throws Exception {
        switch (request.action()) {
            case "LIST" -> out.writeObject(HistoryResponse.history(DatabaseManager.getAnalysisHistory()));
            case "ANALYSIS" -> out.writeObject(
                    HistoryResponse.analysis(DatabaseManager.getAnalysisResultForJob(request.jobId()))
            );
            case "CLEAR" -> {
                DatabaseManager.clearAnalysisHistory();
                out.writeObject(HistoryResponse.success("History cleared"));
            }
            default -> out.writeObject(HistoryResponse.failure("Unknown history action: " + request.action()));
        }
    }

    private static String describeHistoryRequest(HistoryRequest request) {
        return switch (request.action()) {
            case "LIST" -> "HISTORY LIST";
            case "ANALYSIS" -> "HISTORY ANALYSIS jobId=" + request.jobId();
            case "CLEAR" -> "HISTORY CLEAR";
            default -> "HISTORY " + request.action();
        };
    }

    private static String resolveDashboardLabel(Object requestObject) {
        String clientInstanceId = switch (requestObject) {
            case AnalyzeRequest request -> request.clientInstanceId();
            case HistoryRequest request -> request.clientInstanceId();
            default -> null;
        };

        if (clientInstanceId == null || clientInstanceId.isBlank()) {
            return "unknown-dashboard";
        }

        int dashboardNumber = DASHBOARD_CLIENT_NUMBERS.computeIfAbsent(
                clientInstanceId,
                ignored -> DASHBOARD_COUNTER.getAndIncrement()
        );
        return "dashboard-client-" + dashboardNumber;
    }

    private static ThreadFactory createThreadFactory() {
        AtomicInteger counter = new AtomicInteger(1);
        return task -> {
            Thread thread = new Thread(task, "analysis-client-" + counter.getAndIncrement());
            thread.setDaemon(false);
            return thread;
        };
    }
}
