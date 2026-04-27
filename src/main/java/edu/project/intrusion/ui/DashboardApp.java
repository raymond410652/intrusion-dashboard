package edu.project.intrusion.ui;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.ClosedWatchServiceException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import edu.project.intrusion.model.Alert;
import edu.project.intrusion.model.AnalysisJob;
import edu.project.intrusion.model.AnalysisResult;
import edu.project.intrusion.model.LogEntry;
import edu.project.intrusion.net.ClientService;
import edu.project.intrusion.parser.TcpdumpPacketParser;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.beans.property.ReadOnlyStringWrapper;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.chart.BarChart;
import javafx.scene.chart.CategoryAxis;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.XYChart;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressIndicator;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

public class DashboardApp extends Application {

    private final ClientService clientService = new ClientService("localhost", 5060);
    private final ScheduledExecutorService monitorDebouncer = Executors.newSingleThreadScheduledExecutor();
    private final AtomicBoolean tcpdumpAnalysisRunning = new AtomicBoolean(false);

    private TextField fileField;
    private TextField tcpdumpFileField;
    private Label totalLabel;
    private Label failedLabel;
    private Label scanLabel;
    private Label spikeLabel;
    private Label statusLabel;
    private Label tcpdumpStatusLabel;
    private ProgressIndicator progressIndicator;
    private Button analyzeButton;
    private Button startTcpdumpMonitorButton;
    private Button stopTcpdumpMonitorButton;
    private TableView<Alert> alertTable;
    private TableView<AnalysisJob> historyTable;
    private TableView<LogEntry> liveLogTable;
    private Label liveLogCountLabel;
    private BarChart<String, Number> topIpChart;
    private WatchService tcpdumpWatchService;
    private Thread tcpdumpMonitorThread;
    private File tcpdumpFile;
    private ScheduledFuture<?> pendingTcpdumpRefresh;
    private int tcpdumpStartLine;

    @Override
    public void start(Stage stage) {
        stage.setTitle("Network Intrusion Log Analyzer Dashboard");

        fileField = new TextField();
        fileField.setPrefWidth(450);
        fileField.setEditable(false);

        Button browseButton = new Button("Browse CSV");
        analyzeButton = new Button("Analyze");

        progressIndicator = new ProgressIndicator();
        progressIndicator.setVisible(false);
        progressIndicator.setPrefSize(40, 40);

        statusLabel = new Label("Select a CSV file.");

        browseButton.setOnAction(e -> chooseFile(stage));
        analyzeButton.setOnAction(e -> analyzeSelectedFile());

        HBox topBar = new HBox(10, fileField, browseButton, analyzeButton, progressIndicator);
        topBar.setAlignment(Pos.CENTER_LEFT);
        topBar.setPadding(new Insets(10));

        totalLabel = new Label("Total Records: 0");
        failedLabel = new Label("Failed Login IPs: 0");
        scanLabel = new Label("Port Scan IPs: 0");
        spikeLabel = new Label("Traffic Spike Minutes: 0");

        GridPane statsPane = new GridPane();
        statsPane.setHgap(15);
        statsPane.setVgap(10);
        statsPane.add(totalLabel, 0, 0);
        statsPane.add(failedLabel, 1, 0);
        statsPane.add(scanLabel, 0, 1);
        statsPane.add(spikeLabel, 1, 1);
        statsPane.setPadding(new Insets(10));

        alertTable = new TableView<>();
        alertTable.setPlaceholder(new Label("No alerts found."));

        TableColumn<Alert, String> typeCol = new TableColumn<>("Type");
        typeCol.setCellValueFactory(data -> new ReadOnlyStringWrapper(data.getValue().type()));
        typeCol.setPrefWidth(130);

        TableColumn<Alert, String> severityCol = new TableColumn<>("Severity");
        severityCol.setCellValueFactory(data -> new ReadOnlyStringWrapper(data.getValue().severity()));
        severityCol.setPrefWidth(100);

        TableColumn<Alert, String> ipCol = new TableColumn<>("Source IP");
        ipCol.setCellValueFactory(data -> new ReadOnlyStringWrapper(data.getValue().sourceIp()));
        ipCol.setPrefWidth(130);

        TableColumn<Alert, String> messageCol = new TableColumn<>("Message");
        messageCol.setCellValueFactory(data -> new ReadOnlyStringWrapper(data.getValue().message()));
        messageCol.setPrefWidth(450);

        alertTable.getColumns().addAll(List.of(typeCol, severityCol, ipCol, messageCol));
        alertTable.setPrefHeight(250);

        CategoryAxis xAxis = new CategoryAxis();
        xAxis.setLabel("Source IP");

        NumberAxis yAxis = new NumberAxis();
        yAxis.setLabel("Event Count");

        topIpChart = new BarChart<>(xAxis, yAxis);
        topIpChart.setTitle("Top Source IPs");
        topIpChart.setLegendVisible(false);
        topIpChart.setPrefHeight(300);

        VBox dashboardBox = new VBox(15, statsPane, new Label("Alerts"), alertTable, topIpChart, statusLabel);
        dashboardBox.setPadding(new Insets(10));

        historyTable = createHistoryTable();
        Button refreshHistoryButton = new Button("Refresh History");
        Button viewAlertsButton = new Button("View Analysis");
        Button clearHistoryButton = new Button("Clean");
        refreshHistoryButton.setOnAction(e -> loadHistory());
        viewAlertsButton.setOnAction(e -> showSelectedHistoryAnalysis());
        clearHistoryButton.setOnAction(e -> clearHistory());

        HBox historyActions = new HBox(10, refreshHistoryButton, viewAlertsButton, clearHistoryButton);
        historyActions.setAlignment(Pos.CENTER_LEFT);

        VBox historyBox = new VBox(10, historyActions, historyTable);
        historyBox.setPadding(new Insets(10));

        liveLogTable = createLiveLogTable();
        liveLogCountLabel = new Label("Live Rows: 0");
        tcpdumpFileField = new TextField();
        tcpdumpFileField.setPrefWidth(420);
        tcpdumpFileField.setEditable(false);
        Button chooseTcpdumpFileButton = new Button("Choose Tcpdump File");
        startTcpdumpMonitorButton = new Button("Start Tcpdump Monitor");
        stopTcpdumpMonitorButton = new Button("Stop Tcpdump Monitor");
        Button clearLiveLogsButton = new Button("Clean");
        stopTcpdumpMonitorButton.setDisable(true);
        tcpdumpStatusLabel = new Label("Tcpdump monitor stopped.");
        chooseTcpdumpFileButton.setOnAction(e -> chooseTcpdumpFile(stage));
        startTcpdumpMonitorButton.setOnAction(e -> startTcpdumpMonitoring());
        stopTcpdumpMonitorButton.setOnAction(e -> stopTcpdumpMonitoring());
        clearLiveLogsButton.setOnAction(e -> clearLiveLogs());

        HBox tcpdumpBar = new HBox(
                10,
                tcpdumpFileField,
                chooseTcpdumpFileButton,
                startTcpdumpMonitorButton,
                stopTcpdumpMonitorButton,
                clearLiveLogsButton,
                tcpdumpStatusLabel
        );
        tcpdumpBar.setAlignment(Pos.CENTER_LEFT);

        VBox liveLogsBox = new VBox(10, tcpdumpBar, liveLogCountLabel, liveLogTable);
        liveLogsBox.setPadding(new Insets(10));

        TabPane tabPane = new TabPane();
        Tab dashboardTab = new Tab("Dashboard", dashboardBox);
        Tab liveLogsTab = new Tab("Live Logs", liveLogsBox);
        Tab historyTab = new Tab("History", historyBox);
        dashboardTab.setClosable(false);
        liveLogsTab.setClosable(false);
        historyTab.setClosable(false);
        tabPane.getTabs().addAll(List.of(dashboardTab, liveLogsTab, historyTab));

        BorderPane root = new BorderPane();
        root.setTop(topBar);
        root.setCenter(tabPane);

        Scene scene = new Scene(root, 900, 700);
        stage.setScene(scene);
        stage.show();
        loadHistory();
    }

    private void chooseFile(Stage stage) {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Select Log CSV");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("CSV Files", "*.csv"));

        File file = chooser.showOpenDialog(stage);
        if (file != null) {
            fileField.setText(file.getAbsolutePath());
            statusLabel.setText("Ready to analyze: " + file.getName());
        }
    }

    private void chooseTcpdumpFile(Stage stage) {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Select Tcpdump Output File");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text Files", "*.txt", "*.log"));

        File file = chooser.showOpenDialog(stage);
        if (file != null) {
            tcpdumpFile = file;
            tcpdumpStartLine = 0;
            tcpdumpFileField.setText(file.getAbsolutePath());
            tcpdumpStatusLabel.setText("Ready to monitor: " + file.getName());
            refreshTcpdumpLiveLogs();
        }
    }

    private void analyzeSelectedFile() {
        if (fileField.getText().isBlank()) {
            showError("Please select a CSV file first.");
            return;
        }

        File file = new File(fileField.getText());
        if (!file.exists()) {
            showError("Selected file does not exist.");
            return;
        }

        Task<AnalysisResult> task = new Task<>() {
            @Override
            protected AnalysisResult call() throws Exception {
                return clientService.analyzeFile(file);
            }
        };

        statusLabel.setText("Analyzing " + file.getName() + "...");
        analyzeButton.disableProperty().unbind();
        progressIndicator.visibleProperty().unbind();
        analyzeButton.disableProperty().bind(task.runningProperty());
        progressIndicator.visibleProperty().bind(task.runningProperty());

        task.setOnSucceeded(e -> {
            AnalysisResult result = task.getValue();
            updateDashboard(result);
            loadHistory();
            statusLabel.setText("Analysis completed successfully and saved to the database.");
        });

        task.setOnFailed(e -> {
            Throwable ex = task.getException();
            showError(ex == null ? "Unknown error." : ex.getMessage());
            statusLabel.setText("Analysis failed.");
        });

        Thread thread = new Thread(task);
        thread.setDaemon(true);
        thread.start();
    }

    private void startTcpdumpMonitoring() {
        if (tcpdumpFile == null) {
            showError("Please choose a tcpdump output file first.");
            return;
        }

        if (!tcpdumpFile.isFile() || !tcpdumpFile.canRead()) {
            showError("Selected tcpdump file cannot be read.");
            return;
        }

        stopTcpdumpMonitoring();
        try {
            tcpdumpWatchService = FileSystems.getDefault().newWatchService();
            Path parent = tcpdumpFile.toPath().getParent();
            if (parent == null) {
                showError("Selected tcpdump file has no parent folder.");
                return;
            }

            parent.register(
                    tcpdumpWatchService,
                    StandardWatchEventKinds.ENTRY_CREATE,
                    StandardWatchEventKinds.ENTRY_MODIFY
            );

            startTcpdumpMonitorButton.setDisable(true);
            stopTcpdumpMonitorButton.setDisable(false);
            tcpdumpStatusLabel.setText("Monitoring: " + tcpdumpFile.getName());

            tcpdumpMonitorThread = new Thread(() -> watchTcpdumpFile(parent), "tcpdump-file-monitor");
            tcpdumpMonitorThread.setDaemon(true);
            tcpdumpMonitorThread.start();

            refreshTcpdumpLiveLogs();
        } catch (IOException e) {
            showError("Unable to start tcpdump file monitor: " + e.getMessage());
            stopTcpdumpMonitoring();
        }
    }

    private void watchTcpdumpFile(Path parent) {
        while (tcpdumpWatchService != null) {
            try {
                WatchKey key = tcpdumpWatchService.take();
                for (WatchEvent<?> event : key.pollEvents()) {
                    if (event.kind() == StandardWatchEventKinds.OVERFLOW) {
                        continue;
                    }

                    Path changedPath = parent.resolve((Path) event.context());
                    if (changedPath.equals(tcpdumpFile.toPath())) {
                        scheduleTcpdumpRefresh();
                    }
                }

                if (!key.reset()) {
                    break;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (ClosedWatchServiceException e) {
                break;
            } catch (Exception e) {
                Platform.runLater(() -> {
                    tcpdumpStatusLabel.setText("Tcpdump monitor stopped.");
                    showError("Tcpdump monitor failed: " + e.getMessage());
                });
                break;
            }
        }
    }

    private void scheduleTcpdumpRefresh() {
        if (pendingTcpdumpRefresh != null) {
            pendingTcpdumpRefresh.cancel(false);
        }

        pendingTcpdumpRefresh = monitorDebouncer.schedule(
                () -> Platform.runLater(this::refreshTcpdumpLiveLogs),
                2,
                TimeUnit.SECONDS
        );
    }

    private void refreshTcpdumpLiveLogs() {
        if (tcpdumpFile == null || liveLogTable == null) {
            return;
        }

        Task<List<LogEntry>> task = new Task<>() {
            @Override
            protected List<LogEntry> call() throws Exception {
                return parseTcpdumpFile(tcpdumpFile, tcpdumpStartLine);
            }
        };

        task.setOnSucceeded(e -> {
            List<LogEntry> entries = task.getValue();
            setLiveRows(entries);
            if (tcpdumpStatusLabel != null) {
                tcpdumpStatusLabel.setText("Monitoring: " + tcpdumpFile.getName());
            }
            analyzeTcpdumpEntries(entries);
        });

        task.setOnFailed(e -> {
            Throwable ex = task.getException();
            liveLogCountLabel.setText("Live Rows: unavailable");
            if (tcpdumpStatusLabel != null) {
                tcpdumpStatusLabel.setText("Tcpdump monitor stopped.");
            }
            showError(ex == null ? "Unable to load tcpdump logs." : ex.getMessage());
        });

        Thread thread = new Thread(task, "tcpdump-log-refresh");
        thread.setDaemon(true);
        thread.start();
    }

    private void analyzeTcpdumpEntries(List<LogEntry> entries) {
        if (entries.isEmpty() || !tcpdumpAnalysisRunning.compareAndSet(false, true)) {
            return;
        }

        Task<AnalysisResult> task = new Task<>() {
            @Override
            protected AnalysisResult call() throws Exception {
                return clientService.analyzeCsvContent("tcpdump-live-capture.csv", toCsv(entries));
            }
        };

        progressIndicator.visibleProperty().unbind();
        progressIndicator.visibleProperty().bind(task.runningProperty());

        task.setOnSucceeded(e -> {
            tcpdumpAnalysisRunning.set(false);
            updateDashboard(task.getValue());
            loadHistory();
            statusLabel.setText("Tcpdump file analysis completed.");
            if (tcpdumpStatusLabel != null && tcpdumpFile != null) {
                tcpdumpStatusLabel.setText("Monitoring: " + tcpdumpFile.getName());
            }
        });

        task.setOnFailed(e -> {
            tcpdumpAnalysisRunning.set(false);
            Throwable ex = task.getException();
            showError(ex == null ? "Tcpdump analysis failed." : ex.getMessage());
        });

        Thread thread = new Thread(task, "tcpdump-analysis");
        thread.setDaemon(true);
        thread.start();
    }

    private void stopTcpdumpMonitoring() {
        if (pendingTcpdumpRefresh != null) {
            pendingTcpdumpRefresh.cancel(false);
            pendingTcpdumpRefresh = null;
        }

        if (tcpdumpWatchService != null) {
            try {
                tcpdumpWatchService.close();
            } catch (IOException ignored) {
                // Monitor is already stopping.
            }
            tcpdumpWatchService = null;
        }

        if (tcpdumpMonitorThread != null) {
            tcpdumpMonitorThread.interrupt();
            tcpdumpMonitorThread = null;
        }

        if (startTcpdumpMonitorButton != null) {
            startTcpdumpMonitorButton.setDisable(false);
        }
        if (stopTcpdumpMonitorButton != null) {
            stopTcpdumpMonitorButton.setDisable(true);
        }
        if (tcpdumpStatusLabel != null) {
            tcpdumpStatusLabel.setText("Tcpdump monitor stopped.");
        }
    }

    private void updateDashboard(AnalysisResult result) {
        totalLabel.setText("Total Records: " + result.totalRecords());
        failedLabel.setText("Failed Login IPs: " + result.failedLoginIps());
        scanLabel.setText("Port Scan IPs: " + result.portScanIps());
        spikeLabel.setText("Traffic Spike Minutes: " + result.trafficSpikeMinutes());

        alertTable.getItems().setAll(result.alerts());

        topIpChart.getData().clear();
        XYChart.Series<String, Number> series = new XYChart.Series<>();
        for (Map.Entry<String, Integer> entry : result.topSourceIps().entrySet()) {
            series.getData().add(new XYChart.Data<>(entry.getKey(), entry.getValue()));
        }
        topIpChart.getData().add(series);
    }

    private TableView<AnalysisJob> createHistoryTable() {
        TableView<AnalysisJob> table = new TableView<>();
        table.setPlaceholder(new Label("No saved analysis history."));

        TableColumn<AnalysisJob, String> idCol = new TableColumn<>("Job ID");
        idCol.setCellValueFactory(data -> new ReadOnlyStringWrapper(
                Long.toString(data.getValue().id())
        ));
        idCol.setPrefWidth(80);

        TableColumn<AnalysisJob, String> fileCol = new TableColumn<>("File");
        fileCol.setCellValueFactory(data -> new ReadOnlyStringWrapper(data.getValue().fileName()));
        fileCol.setPrefWidth(240);

        TableColumn<AnalysisJob, String> totalCol = new TableColumn<>("Records");
        totalCol.setCellValueFactory(data -> new ReadOnlyStringWrapper(
                Integer.toString(data.getValue().totalRecords())
        ));
        totalCol.setPrefWidth(100);

        TableColumn<AnalysisJob, String> suspiciousCol = new TableColumn<>("Alerts");
        suspiciousCol.setCellValueFactory(data -> new ReadOnlyStringWrapper(
                Integer.toString(data.getValue().suspiciousRecords())
        ));
        suspiciousCol.setPrefWidth(100);

        TableColumn<AnalysisJob, String> createdCol = new TableColumn<>("Created");
        createdCol.setCellValueFactory(data -> new ReadOnlyStringWrapper(data.getValue().createdAt()));
        createdCol.setPrefWidth(180);

        table.getColumns().addAll(List.of(idCol, fileCol, totalCol, suspiciousCol, createdCol));
        return table;
    }

    private TableView<LogEntry> createLiveLogTable() {
        TableView<LogEntry> table = new TableView<>();
        table.setPlaceholder(new Label("Choose and start monitoring a log file."));

        TableColumn<LogEntry, String> timeCol = new TableColumn<>("Timestamp");
        timeCol.setCellValueFactory(data -> new ReadOnlyStringWrapper(data.getValue().timestamp()));
        timeCol.setPrefWidth(170);

        TableColumn<LogEntry, String> sourceIpCol = new TableColumn<>("Source IP");
        sourceIpCol.setCellValueFactory(data -> new ReadOnlyStringWrapper(data.getValue().sourceIp()));
        sourceIpCol.setPrefWidth(130);

        TableColumn<LogEntry, String> destinationIpCol = new TableColumn<>("Destination IP");
        destinationIpCol.setCellValueFactory(data -> new ReadOnlyStringWrapper(data.getValue().destinationIp()));
        destinationIpCol.setPrefWidth(140);

        TableColumn<LogEntry, String> sourcePortCol = new TableColumn<>("Source Port");
        sourcePortCol.setCellValueFactory(data -> new ReadOnlyStringWrapper(
                Integer.toString(data.getValue().sourcePort())
        ));
        sourcePortCol.setPrefWidth(100);

        TableColumn<LogEntry, String> destinationPortCol = new TableColumn<>("Destination Port");
        destinationPortCol.setCellValueFactory(data -> new ReadOnlyStringWrapper(
                Integer.toString(data.getValue().destinationPort())
        ));
        destinationPortCol.setPrefWidth(120);

        TableColumn<LogEntry, String> protocolCol = new TableColumn<>("Protocol");
        protocolCol.setCellValueFactory(data -> new ReadOnlyStringWrapper(data.getValue().protocol()));
        protocolCol.setPrefWidth(90);

        TableColumn<LogEntry, String> statusCol = new TableColumn<>("Status");
        statusCol.setCellValueFactory(data -> new ReadOnlyStringWrapper(
                Integer.toString(data.getValue().statusCode())
        ));
        statusCol.setPrefWidth(80);

        TableColumn<LogEntry, String> sizeCol = new TableColumn<>("Data Size");
        sizeCol.setCellValueFactory(data -> new ReadOnlyStringWrapper(
                Integer.toString(data.getValue().dataSize())
        ));
        sizeCol.setPrefWidth(90);

        table.getColumns().addAll(List.of(
                timeCol,
                sourceIpCol,
                destinationIpCol,
                sourcePortCol,
                destinationPortCol,
                protocolCol,
                statusCol,
                sizeCol
        ));
        return table;
    }

    private void setLiveRows(List<LogEntry> entries) {
        liveLogTable.getItems().setAll(entries);
        liveLogCountLabel.setText("Live Rows: " + entries.size());
        if (!entries.isEmpty()) {
            liveLogTable.scrollTo(entries.size() - 1);
        }
    }

    private List<LogEntry> parseTcpdumpFile(File file, int startLine) throws IOException {
        TcpdumpPacketParser parser = new TcpdumpPacketParser();
        return Files.readAllLines(file.toPath(), StandardCharsets.UTF_8).stream()
                .skip(Math.max(0, startLine))
                .map(parser::parse)
                .flatMap(Optional::stream)
                .toList();
    }

    private String toCsv(List<LogEntry> entries) {
        StringBuilder csv = new StringBuilder();
        csv.append("timestamp,sourceIp,destinationIp,sourcePort,destinationPort,protocol,statusCode,dataSize\n");

        for (LogEntry entry : entries) {
            csv.append(entry.timestamp()).append(',')
                    .append(entry.sourceIp()).append(',')
                    .append(entry.destinationIp()).append(',')
                    .append(entry.sourcePort()).append(',')
                    .append(entry.destinationPort()).append(',')
                    .append(entry.protocol()).append(',')
                    .append(entry.statusCode()).append(',')
                    .append(entry.dataSize()).append('\n');
        }

        return csv.toString();
    }

    private void loadHistory() {
        Task<List<AnalysisJob>> task = new Task<>() {
            @Override
            protected List<AnalysisJob> call() throws Exception {
                return clientService.loadHistory();
            }
        };

        task.setOnSucceeded(e -> historyTable.getItems().setAll(task.getValue()));
        task.setOnFailed(e -> {
            Throwable ex = task.getException();
            showError(ex == null ? "Unable to load history." : ex.getMessage());
        });

        Thread thread = new Thread(task);
        thread.setDaemon(true);
        thread.start();
    }

    private void clearHistory() {
        if (!confirm("Clear saved history?", "This will remove all saved analysis history from the database.")) {
            return;
        }

        Task<Void> task = new Task<>() {
            @Override
            protected Void call() throws Exception {
                clientService.clearHistory();
                return null;
            }
        };

        task.setOnSucceeded(e -> {
            historyTable.getItems().clear();
            resetDashboard();
            statusLabel.setText("History database cleared.");
        });

        task.setOnFailed(e -> {
            Throwable ex = task.getException();
            showError(ex == null ? "Unable to clear history." : ex.getMessage());
        });

        Thread thread = new Thread(task, "history-clear");
        thread.setDaemon(true);
        thread.start();
    }

    private void showSelectedHistoryAnalysis() {
        AnalysisJob selectedJob = historyTable.getSelectionModel().getSelectedItem();
        if (selectedJob == null) {
            showError("Please select a history row first.");
            return;
        }

        Task<AnalysisResult> task = new Task<>() {
            @Override
            protected AnalysisResult call() throws Exception {
                return clientService.loadAnalysisForJob(selectedJob.id());
            }
        };

        task.setOnSucceeded(e -> {
            AnalysisResult result = task.getValue();
            updateDashboard(result);
            statusLabel.setText("Loaded analysis for database job #" + selectedJob.id()
                    + " (" + selectedJob.fileName() + ").");
        });

        task.setOnFailed(e -> {
            Throwable ex = task.getException();
            showError(ex == null ? "Unable to load saved analysis." : ex.getMessage());
        });

        Thread thread = new Thread(task);
        thread.setDaemon(true);
        thread.start();
    }

    private void clearLiveLogs() {
        if (tcpdumpFile == null) {
            setLiveRows(List.of());
            liveLogTable.setPlaceholder(new Label("Choose and start monitoring a tcpdump file."));
            tcpdumpStatusLabel.setText("Live log view cleared.");
            return;
        }

        try {
            tcpdumpStartLine = Files.readAllLines(tcpdumpFile.toPath(), StandardCharsets.UTF_8).size();
            setLiveRows(List.of());
            tcpdumpStatusLabel.setText("Cleared previous live logs. Waiting for new packets...");
        } catch (IOException e) {
            showError("Unable to clear live logs: " + e.getMessage());
        }
    }

    private void resetDashboard() {
        totalLabel.setText("Total Records: 0");
        failedLabel.setText("Failed Login IPs: 0");
        scanLabel.setText("Port Scan IPs: 0");
        spikeLabel.setText("Traffic Spike Minutes: 0");
        alertTable.getItems().clear();
        topIpChart.getData().clear();
    }

    private boolean confirm(String title, String message) {
        javafx.scene.control.Alert alert =
                new javafx.scene.control.Alert(AlertType.CONFIRMATION);
        alert.setTitle(title);
        alert.setHeaderText(title);
        alert.setContentText(message);
        return alert.showAndWait().filter(ButtonType.OK::equals).isPresent();
    }

    private void showError(String message) {
        javafx.scene.control.Alert alert =
                new javafx.scene.control.Alert(AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText("Operation Failed");
        alert.setContentText(message);
        alert.showAndWait();
    }

    @Override
    public void stop() {
        stopTcpdumpMonitoring();
        monitorDebouncer.shutdownNow();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
