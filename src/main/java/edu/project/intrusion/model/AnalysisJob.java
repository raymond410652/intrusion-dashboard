package edu.project.intrusion.model;

import java.io.Serializable;

public record AnalysisJob(
        long id,
        String fileName,
        int totalRecords,
        int suspiciousRecords,
        String createdAt
) implements Serializable {
    private static final long serialVersionUID = 1L;

    public AnalysisJob {
        fileName = normalize(fileName);
        createdAt = normalize(createdAt);
        totalRecords = Math.max(totalRecords, 0);
        suspiciousRecords = Math.max(suspiciousRecords, 0);
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim();
    }
}
