package edu.project.intrusion.parser;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import edu.project.intrusion.model.LogEntry;

public class TcpdumpPacketParser {

    private static final Pattern TCP_UDP_PATTERN = Pattern.compile(
            ".*\\b(IP6?|ARP)\\s+([0-9a-fA-F:.]+)\\.(\\d+)\\s+>\\s+([0-9a-fA-F:.]+)\\.(\\d+):.*(?:length\\s+(\\d+))?.*"
    );

    private static final Pattern ICMP_PATTERN = Pattern.compile(
            ".*\\b(IP6?)\\s+([0-9a-fA-F:.]+)\\s+>\\s+([0-9a-fA-F:.]+):\\s+ICMP.*"
    );

    public Optional<LogEntry> parse(String line) {
        if (line == null || line.isBlank()) {
            return Optional.empty();
        }

        Matcher tcpUdpMatcher = TCP_UDP_PATTERN.matcher(line);
        if (tcpUdpMatcher.matches()) {
            return Optional.of(new LogEntry(
                    LocalDateTime.now().withNano(0).toString(),
                    tcpUdpMatcher.group(2),
                    tcpUdpMatcher.group(4),
                    parseInt(tcpUdpMatcher.group(3)),
                    parseInt(tcpUdpMatcher.group(5)),
                    detectProtocol(line),
                    200,
                    parseInt(tcpUdpMatcher.group(6))
            ));
        }

        Matcher icmpMatcher = ICMP_PATTERN.matcher(line);
        if (icmpMatcher.matches()) {
            return Optional.of(new LogEntry(
                    LocalDateTime.now().withNano(0).toString(),
                    icmpMatcher.group(2),
                    icmpMatcher.group(3),
                    0,
                    0,
                    "ICMP",
                    200,
                    0
            ));
        }

        return Optional.empty();
    }

    private String detectProtocol(String line) {
        if (line.contains(" UDP,")) {
            return "UDP";
        }
        if (line.contains(" ICMP")) {
            return "ICMP";
        }
        return "TCP";
    }

    private int parseInt(String value) {
        if (value == null || value.isBlank()) {
            return 0;
        }

        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
