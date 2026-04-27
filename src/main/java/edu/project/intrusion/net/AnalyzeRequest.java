package edu.project.intrusion.net;

import java.io.Serializable;

public record AnalyzeRequest(
        String clientInstanceId,
        String fileName,
        String csvContent
) implements Serializable {
    private static final long serialVersionUID = 1L;

    public AnalyzeRequest {
        clientInstanceId = normalize(clientInstanceId);
        fileName = normalize(fileName);
        csvContent = csvContent == null ? "" : csvContent;
        if (clientInstanceId.isBlank()) {
            throw new IllegalArgumentException("clientInstanceId is required");
        }
        if (fileName.isBlank()) {
            throw new IllegalArgumentException("fileName is required");
        }
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim();
    }
}
