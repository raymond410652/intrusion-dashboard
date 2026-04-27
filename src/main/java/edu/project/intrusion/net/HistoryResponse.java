package edu.project.intrusion.net;

import java.io.Serializable;
import java.util.List;

import edu.project.intrusion.model.AnalysisJob;
import edu.project.intrusion.model.AnalysisResult;

public record HistoryResponse(
        boolean success,
        String message,
        List<AnalysisJob> history,
        AnalysisResult result
) implements Serializable {
    private static final long serialVersionUID = 1L;

    public HistoryResponse {
        message = message == null ? "" : message.trim();
        history = List.copyOf(history == null ? List.of() : history);
    }

    public static HistoryResponse history(List<AnalysisJob> history) {
        return new HistoryResponse(true, "History loaded", history, null);
    }

    public static HistoryResponse analysis(AnalysisResult result) {
        return new HistoryResponse(true, "Analysis loaded", List.of(), result);
    }

    public static HistoryResponse failure(String message) {
        return new HistoryResponse(false, message, List.of(), null);
    }
}
