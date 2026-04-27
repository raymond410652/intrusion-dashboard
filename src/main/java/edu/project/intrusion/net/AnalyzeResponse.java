package edu.project.intrusion.net;

import java.io.Serializable;

import edu.project.intrusion.model.AnalysisResult;

public record AnalyzeResponse(
        boolean success,
        String message,
        AnalysisResult result
) implements Serializable {
    private static final long serialVersionUID = 1L;
}
