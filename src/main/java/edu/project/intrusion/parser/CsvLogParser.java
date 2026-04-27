package edu.project.intrusion.parser;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import edu.project.intrusion.model.LogEntry;

public class CsvLogParser {

    private static final Logger LOGGER = Logger.getLogger(CsvLogParser.class.getName());
    private static final int EXPECTED_COLUMNS = 8;

    public List<LogEntry> parse(String csvContent) {
        if (csvContent == null || csvContent.isBlank()) {
            return List.of();
        }

        List<LogEntry> entries = new ArrayList<>();
        String[] lines = csvContent.split("\\R");

        for (int i = 1; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty()) {
                continue;
            }

            List<String> parts = parseCsvLine(line);
            if (parts.size() < EXPECTED_COLUMNS) {
                LOGGER.warning("Skipping row " + (i + 1) + ": expected at least "
                        + EXPECTED_COLUMNS + " columns but found " + parts.size());
                continue;
            }

            try {
                entries.add(new LogEntry(
                        parts.get(0),
                        parts.get(1),
                        parts.get(2),
                        parseInt(parts.get(3)),
                        parseInt(parts.get(4)),
                        parts.get(5),
                        parseInt(parts.get(6)),
                        parseInt(parts.get(7))
                ));
            } catch (IllegalArgumentException e) {
                LOGGER.warning("Skipping row " + (i + 1) + ": " + e.getMessage());
            }
        }

        return entries;
    }

    private List<String> parseCsvLine(String line) {
        List<String> values = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;

        for (int i = 0; i < line.length(); i++) {
            char ch = line.charAt(i);
            if (ch == '"') {
                if (inQuotes && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    current.append(ch);
                    i++;
                } else {
                    inQuotes = !inQuotes;
                }
            } else if (ch == ',' && !inQuotes) {
                values.add(current.toString().trim());
                current.setLength(0);
            } else {
                current.append(ch);
            }
        }

        values.add(current.toString().trim());
        return values;
    }

    private int parseInt(String value) {
        try {
            return Integer.parseInt(value.trim());
        } catch (Exception e) {
            return 0;
        }
    }
}
