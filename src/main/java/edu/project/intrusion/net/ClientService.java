package edu.project.intrusion.net;

import java.io.File;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import edu.project.intrusion.model.AnalysisJob;
import edu.project.intrusion.model.AnalysisResult;

public class ClientService {

    private static final int CONNECT_TIMEOUT_MS = 5_000;
    private static final int READ_TIMEOUT_MS = 30_000;

    private final String host;
    private final int port;
    private final String clientInstanceId = UUID.randomUUID().toString();

    public ClientService(String host, int port) {
        this.host = Objects.requireNonNull(host, "host").trim();
        if (this.host.isBlank()) {
            throw new IllegalArgumentException("host is required");
        }
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("port must be between 1 and 65535");
        }
        this.port = port;
    }

    public AnalysisResult analyzeFile(File file) throws Exception {
        Objects.requireNonNull(file, "file");
        if (!file.isFile() || !file.canRead()) {
            throw new IllegalArgumentException("Selected file cannot be read.");
        }

        String csvContent = Files.readString(file.toPath(), StandardCharsets.UTF_8);
        return analyzeCsvContent(file.getName(), csvContent);
    }

    public AnalysisResult analyzeCsvContent(String fileName, String csvContent) throws Exception {
        AnalyzeRequest request = new AnalyzeRequest(clientInstanceId, fileName, csvContent);

        Object responseObject = sendRequest(request);
        if (!(responseObject instanceof AnalyzeResponse response)) {
            throw new RuntimeException("Invalid analysis response from server.");
        }

        if (!response.success()) {
            throw new RuntimeException(response.message());
        }

        return response.result();
    }

    public List<AnalysisJob> loadHistory() throws Exception {
        Object responseObject = sendRequest(HistoryRequest.listHistory(clientInstanceId));
        if (!(responseObject instanceof HistoryResponse response)) {
            throw new RuntimeException("Invalid history response from server.");
        }

        if (!response.success()) {
            throw new RuntimeException(response.message());
        }

        return response.history();
    }

    public AnalysisResult loadAnalysisForJob(long jobId) throws Exception {
        Object responseObject = sendRequest(HistoryRequest.analysisForJob(clientInstanceId, jobId));
        if (!(responseObject instanceof HistoryResponse response)) {
            throw new RuntimeException("Invalid history response from server.");
        }

        if (!response.success()) {
            throw new RuntimeException(response.message());
        }

        return response.result();
    }

    public void clearHistory() throws Exception {
        Object responseObject = sendRequest(HistoryRequest.clearHistory(clientInstanceId));
        if (!(responseObject instanceof HistoryResponse response)) {
            throw new RuntimeException("Invalid history response from server.");
        }

        if (!response.success()) {
            throw new RuntimeException(response.message());
        }
    }

    public String clientInstanceId() {
        return clientInstanceId;
    }

    private Object sendRequest(Object request) throws Exception {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            socket.setSoTimeout(READ_TIMEOUT_MS);

            try (ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                 ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

                out.flush();

                out.writeObject(request);
                out.flush();

                return in.readObject();
            }
        }
    }
}
