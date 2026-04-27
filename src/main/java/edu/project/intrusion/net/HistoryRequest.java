package edu.project.intrusion.net;

import java.io.Serializable;

public record HistoryRequest(
        String action,
        long jobId
) implements Serializable {
    private static final long serialVersionUID = 1L;

    public static HistoryRequest listHistory() {
        return new HistoryRequest("LIST", -1);
    }

    public static HistoryRequest analysisForJob(long jobId) {
        return new HistoryRequest("ANALYSIS", jobId);
    }

    public HistoryRequest {
        action = action == null ? "" : action.trim().toUpperCase();
    }
}
