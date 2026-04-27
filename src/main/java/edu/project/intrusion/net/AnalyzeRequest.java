package edu.project.intrusion.net;

import java.io.Serializable;

public record AnalyzeRequest(
        String fileName,
        String csvContent
) implements Serializable {
    private static final long serialVersionUID = 1L;

    public AnalyzeRequest {
        fileName = normalize(fileName);
        csvContent = csvContent == null ? "" : csvContent;
        if (fileName.isBlank()) {
            throw new IllegalArgumentException("fileName is required");
        }
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim();
    }
}
