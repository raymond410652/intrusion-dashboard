package edu.project.intrusion.model;

import java.io.Serializable;

public record LogEntry(
        String timestamp,
        String sourceIp,
        String destinationIp,
        int sourcePort,
        int destinationPort,
        String protocol,
        int statusCode,
        int dataSize
) implements Serializable {
    private static final long serialVersionUID = 1L;

    public LogEntry {
        timestamp = normalize(timestamp);
        sourceIp = normalize(sourceIp);
        destinationIp = normalize(destinationIp);
        protocol = normalize(protocol).toUpperCase();
        sourcePort = requirePort(sourcePort, "sourcePort");
        destinationPort = requirePort(destinationPort, "destinationPort");
        statusCode = Math.max(statusCode, 0);
        dataSize = Math.max(dataSize, 0);
    }

    private static int requirePort(int value, String fieldName) {
        if (value < 0 || value > 65535) {
            throw new IllegalArgumentException(fieldName + " must be between 0 and 65535");
        }
        return value;
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim();
    }
}
