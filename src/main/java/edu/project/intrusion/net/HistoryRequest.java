package edu.project.intrusion.net;

import java.io.Serializable;

public record HistoryRequest(
        String clientInstanceId,
        String action,
        long jobId
) implements Serializable {
    private static final long serialVersionUID = 1L;

    public static HistoryRequest listHistory(String clientInstanceId) {
        return new HistoryRequest(clientInstanceId, "LIST", -1);
    }

    public static HistoryRequest analysisForJob(String clientInstanceId, long jobId) {
        return new HistoryRequest(clientInstanceId, "ANALYSIS", jobId);
    }

    public static HistoryRequest clearHistory(String clientInstanceId) {
        return new HistoryRequest(clientInstanceId, "CLEAR", -1);
    }

    public HistoryRequest {
        clientInstanceId = clientInstanceId == null ? "" : clientInstanceId.trim();
        action = action == null ? "" : action.trim().toUpperCase();
        if (clientInstanceId.isBlank()) {
            throw new IllegalArgumentException("clientInstanceId is required");
        }
    }
}
