package edu.project.intrusion.db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import edu.project.intrusion.model.Alert;
import edu.project.intrusion.model.AnalysisJob;
import edu.project.intrusion.model.AnalysisResult;
import edu.project.intrusion.model.LogEntry;

public class DatabaseManager {

    private static final String DEFAULT_DB_URL = "jdbc:sqlite:intrusion_dashboard.db";
    private static final String DB_URL_PROPERTY = "intrusion.db.url";

    public static void initDatabase() {
        String createJobsTable = """
                CREATE TABLE IF NOT EXISTS analysis_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_name TEXT NOT NULL,
                    total_records INTEGER NOT NULL,
                    suspicious_records INTEGER NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """;

        String createLogsTable = """
                CREATE TABLE IF NOT EXISTS log_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id INTEGER NOT NULL,
                    timestamp TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol TEXT,
                    status_code INTEGER,
                    data_size INTEGER,
                    FOREIGN KEY(job_id) REFERENCES analysis_jobs(id)
                )
                """;

        String createAlertsTable = """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id INTEGER NOT NULL,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    source_ip TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(job_id) REFERENCES analysis_jobs(id)
                )
                """;

        String createLogJobIndex = """
                CREATE INDEX IF NOT EXISTS idx_log_events_job_id
                ON log_events(job_id)
                """;

        String createAlertJobIndex = """
                CREATE INDEX IF NOT EXISTS idx_alerts_job_id
                ON alerts(job_id)
                """;

        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {

            stmt.execute("PRAGMA journal_mode = WAL");
            stmt.execute(createJobsTable);
            stmt.execute(createLogsTable);
            stmt.execute(createAlertsTable);
            stmt.execute(createLogJobIndex);
            stmt.execute(createAlertJobIndex);

            System.out.println("Database initialized at " + getDatabaseUrl());

        } catch (SQLException e) {
            throw new RuntimeException("Database initialization failed", e);
        }
    }

    public static boolean canConnect() {
        try (Connection conn = getConnection()) {
            return conn.isValid(2);
        } catch (SQLException e) {
            return false;
        }
    }

    public static long saveAnalysis(String fileName, List<LogEntry> entries, AnalysisResult result) {
        if (fileName == null || fileName.isBlank()) {
            throw new IllegalArgumentException("fileName is required");
        }
        if (entries == null) {
            throw new IllegalArgumentException("entries is required");
        }
        if (result == null) {
            throw new IllegalArgumentException("result is required");
        }

        String insertJob = """
                INSERT INTO analysis_jobs(file_name, total_records, suspicious_records)
                VALUES(?, ?, ?)
                """;

        String insertLog = """
                INSERT INTO log_events(job_id, timestamp, source_ip, destination_ip,
                source_port, destination_port, protocol, status_code, data_size)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                """;

        String insertAlert = """
                INSERT INTO alerts(job_id, type, severity, message, source_ip)
                VALUES(?, ?, ?, ?, ?)
                """;

        try (Connection conn = getConnection()) {
            conn.setAutoCommit(false);

            try {
                long jobId;

                try (PreparedStatement ps = conn.prepareStatement(insertJob, Statement.RETURN_GENERATED_KEYS)) {
                    ps.setString(1, fileName);
                    ps.setInt(2, result.totalRecords());
                    ps.setInt(3, result.alerts().size());
                    ps.executeUpdate();

                    try (ResultSet rs = ps.getGeneratedKeys()) {
                        if (!rs.next()) {
                            throw new SQLException("Failed to retrieve job id.");
                        }
                        jobId = rs.getLong(1);
                    }
                }

                try (PreparedStatement ps = conn.prepareStatement(insertLog)) {
                    for (LogEntry entry : entries) {
                        ps.setLong(1, jobId);
                        ps.setString(2, entry.timestamp());
                        ps.setString(3, entry.sourceIp());
                        ps.setString(4, entry.destinationIp());
                        ps.setInt(5, entry.sourcePort());
                        ps.setInt(6, entry.destinationPort());
                        ps.setString(7, entry.protocol());
                        ps.setInt(8, entry.statusCode());
                        ps.setInt(9, entry.dataSize());
                        ps.addBatch();
                    }
                    ps.executeBatch();
                }

                try (PreparedStatement ps = conn.prepareStatement(insertAlert)) {
                    for (Alert alert : result.alerts()) {
                        ps.setLong(1, jobId);
                        ps.setString(2, alert.type());
                        ps.setString(3, alert.severity());
                        ps.setString(4, alert.message());
                        ps.setString(5, alert.sourceIp());
                        ps.addBatch();
                    }
                    ps.executeBatch();
                }

                conn.commit();
                System.out.println("Analysis saved to database with job id " + jobId);
                return jobId;
            } catch (SQLException e) {
                conn.rollback();
                throw e;
            }

        } catch (SQLException e) {
            throw new RuntimeException("Saving analysis failed", e);
        }
    }

    public static List<AnalysisJob> getAnalysisHistory() {
        String query = """
                SELECT id, file_name, total_records, suspicious_records, created_at
                FROM analysis_jobs
                ORDER BY datetime(created_at) DESC, id DESC
                """;

        List<AnalysisJob> jobs = new ArrayList<>();

        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(query);
             ResultSet rs = ps.executeQuery()) {

            while (rs.next()) {
                jobs.add(new AnalysisJob(
                        rs.getLong("id"),
                        rs.getString("file_name"),
                        rs.getInt("total_records"),
                        rs.getInt("suspicious_records"),
                        rs.getString("created_at")
                ));
            }

            return jobs;
        } catch (SQLException e) {
            throw new RuntimeException("Loading analysis history failed", e);
        }
    }

    public static List<Alert> getAlertsForJob(long jobId) {
        String query = """
                SELECT type, severity, message, source_ip
                FROM alerts
                WHERE job_id = ?
                ORDER BY id
                """;

        List<Alert> alerts = new ArrayList<>();

        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(query)) {

            ps.setLong(1, jobId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    alerts.add(new Alert(
                            rs.getString("type"),
                            rs.getString("severity"),
                            rs.getString("message"),
                            rs.getString("source_ip")
                    ));
                }
            }

            return alerts;
        } catch (SQLException e) {
            throw new RuntimeException("Loading alerts for job " + jobId + " failed", e);
        }
    }

    public static AnalysisResult getAnalysisResultForJob(long jobId) {
        AnalysisJob job = getAnalysisJob(jobId);
        List<Alert> alerts = getAlertsForJob(jobId);
        Map<String, Integer> topSourceIps = getTopSourceIpsForJob(jobId);

        int failedLoginIps = (int) alerts.stream()
                .filter(alert -> "FAILED_LOGIN".equals(alert.type()))
                .map(Alert::sourceIp)
                .distinct()
                .count();

        int portScanIps = (int) alerts.stream()
                .filter(alert -> "PORT_SCAN".equals(alert.type()))
                .map(Alert::sourceIp)
                .distinct()
                .count();

        int trafficSpikeMinutes = (int) alerts.stream()
                .filter(alert -> "TRAFFIC_SPIKE".equals(alert.type()))
                .count();

        return new AnalysisResult(
                job.totalRecords(),
                failedLoginIps,
                portScanIps,
                trafficSpikeMinutes,
                alerts,
                topSourceIps
        );
    }

    public static void clearAnalysisHistory() {
        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {
            conn.setAutoCommit(false);
            try {
                stmt.executeUpdate("DELETE FROM alerts");
                stmt.executeUpdate("DELETE FROM log_events");
                stmt.executeUpdate("DELETE FROM analysis_jobs");
                stmt.executeUpdate("DELETE FROM sqlite_sequence WHERE name IN ('alerts', 'log_events', 'analysis_jobs')");
                conn.commit();
                System.out.println("Analysis history cleared.");
            } catch (SQLException e) {
                conn.rollback();
                throw e;
            }
        } catch (SQLException e) {
            throw new RuntimeException("Clearing analysis history failed", e);
        }
    }

    private static AnalysisJob getAnalysisJob(long jobId) {
        String query = """
                SELECT id, file_name, total_records, suspicious_records, created_at
                FROM analysis_jobs
                WHERE id = ?
                """;

        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(query)) {

            ps.setLong(1, jobId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    throw new SQLException("Analysis job " + jobId + " was not found.");
                }

                return new AnalysisJob(
                        rs.getLong("id"),
                        rs.getString("file_name"),
                        rs.getInt("total_records"),
                        rs.getInt("suspicious_records"),
                        rs.getString("created_at")
                );
            }
        } catch (SQLException e) {
            throw new RuntimeException("Loading analysis job " + jobId + " failed", e);
        }
    }

    private static Map<String, Integer> getTopSourceIpsForJob(long jobId) {
        String query = """
                SELECT source_ip, COUNT(*) AS event_count
                FROM log_events
                WHERE job_id = ?
                  AND source_ip IS NOT NULL
                  AND TRIM(source_ip) <> ''
                GROUP BY source_ip
                ORDER BY event_count DESC, source_ip ASC
                LIMIT 5
                """;

        Map<String, Integer> topSourceIps = new LinkedHashMap<>();

        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(query)) {

            ps.setLong(1, jobId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    topSourceIps.put(rs.getString("source_ip"), rs.getInt("event_count"));
                }
            }

            return topSourceIps;
        } catch (SQLException e) {
            throw new RuntimeException("Loading top source IPs for job " + jobId + " failed", e);
        }
    }

    private static Connection getConnection() throws SQLException {
        Connection conn = DriverManager.getConnection(getDatabaseUrl());
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("PRAGMA foreign_keys = ON");
            stmt.execute("PRAGMA busy_timeout = 10000");
        }
        return conn;
    }

    private static String getDatabaseUrl() {
        return System.getProperty(DB_URL_PROPERTY, DEFAULT_DB_URL);
    }
}
