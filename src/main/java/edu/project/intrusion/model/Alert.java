package edu.project.intrusion.model;

import java.io.Serializable;

public record Alert(
        String type,
        String severity,
        String message,
        String sourceIp
) implements Serializable {
    private static final long serialVersionUID = 1L;

    public Alert {
        type = requireText(type, "type");
        severity = requireText(severity, "severity");
        message = requireText(message, "message");
        sourceIp = normalize(sourceIp);
    }

    private static String requireText(String value, String fieldName) {
        String normalized = normalize(value);
        if (normalized.isBlank()) {
            throw new IllegalArgumentException(fieldName + " is required");
        }
        return normalized;
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim();
    }
}
