package edu.project.intrusion.ui;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.ClosedWatchServiceException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
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
import edu.project.intrusion.parser.CsvLogParser;
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
    private final AtomicBoolean monitorAnalysisRunning = new AtomicBoolean(false);
    private final List<LogEntry> capturedEntries = Collections.synchronizedList(new ArrayList<>());
    private final AtomicBoolean captureAnalysisRunning = new AtomicBoolean(false);

    private TextField fileField;
    private TextField monitorFileField;
    private Label totalLabel;
    private Label failedLabel;
    private Label scanLabel;
    private Label spikeLabel;
    private Label statusLabel;
    private Label monitorStatusLabel;
    private Label captureStatusLabel;
    private ProgressIndicator progressIndicator;
    private Button analyzeButton;
    private Button startMonitorButton;
    private Button stopMonitorButton;
    private Button startCaptureButton;
    private Button stopCaptureButton;
    private TextField captureInterfaceField;
    private TableView<Alert> alertTable;
    private TableView<AnalysisJob> historyTable;
    private TableView<LogEntry> liveLogTable;
    private Label liveLogCountLabel;
    private BarChart<String, Number> topIpChart;
    private WatchService watchService;
    private Thread monitorThread;
    private File monitoredFile;
    private ScheduledFuture<?> pendingMonitorAnalysis;
    private Process captureProcess;
    private Thread captureThread;
    private ScheduledFuture<?> pendingCaptureAnalysis;

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

        monitorFileField = new TextField();
        monitorFileField.setPrefWidth(450);
        monitorFileField.setEditable(false);

        Button chooseMonitorButton = new Button("Choose Monitor File");
        startMonitorButton = new Button("Start Monitor");
        stopMonitorButton = new Button("Stop Monitor");
        stopMonitorButton.setDisable(true);

        monitorStatusLabel = new Label("Monitor stopped.");

        chooseMonitorButton.setOnAction(e -> chooseMonitorFile(stage));
        startMonitorButton.setOnAction(e -> startMonitoring());
        stopMonitorButton.setOnAction(e -> stopMonitoring());

        HBox monitorBar = new HBox(
                10,
                monitorFileField,
                chooseMonitorButton,
                startMonitorButton,
                stopMonitorButton,
                monitorStatusLabel
        );
        monitorBar.setAlignment(Pos.CENTER_LEFT);
        monitorBar.setPadding(new Insets(10, 10, 0, 10));

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

        VBox dashboardBox = new VBox(15, monitorBar, statsPane, new Label("Alerts"), alertTable, topIpChart, statusLabel);
        dashboardBox.setPadding(new Insets(10));

        historyTable = createHistoryTable();
        Button refreshHistoryButton = new Button("Refresh History");
        Button viewAlertsButton = new Button("View Analysis");
        refreshHistoryButton.setOnAction(e -> loadHistory());
        viewAlertsButton.setOnAction(e -> showSelectedHistoryAnalysis());

        HBox historyActions = new HBox(10, refreshHistoryButton, viewAlertsButton);
        historyActions.setAlignment(Pos.CENTER_LEFT);

        VBox historyBox = new VBox(10, historyActions, historyTable);
        historyBox.setPadding(new Insets(10));

        liveLogTable = createLiveLogTable();
        liveLogCountLabel = new Label("Live Rows: 0");

        captureInterfaceField = new TextField("en0");
        captureInterfaceField.setPrefWidth(90);
        startCaptureButton = new Button("Start Capture");
        stopCaptureButton = new Button("Stop Capture");
        stopCaptureButton.setDisable(true);
        captureStatusLabel = new Label("Packet capture stopped.");
        startCaptureButton.setOnAction(e -> startPacketCapture());
        stopCaptureButton.setOnAction(e -> stopPacketCapture());

        HBox captureBar = new HBox(
                10,
                new Label("Interface"),
                captureInterfaceField,
                startCaptureButton,
                stopCaptureButton,
                captureStatusLabel
        );
        captureBar.setAlignment(Pos.CENTER_LEFT);

        VBox liveLogsBox = new VBox(10, captureBar, liveLogCountLabel, liveLogTable);
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

    private void chooseMonitorFile(Stage stage) {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Select Log File to Monitor");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("CSV Files", "*.csv"));

        File file = chooser.showOpenDialog(stage);
        if (file != null) {
            monitoredFile = file;
            monitorFileField.setText(file.getAbsolutePath());
            monitorStatusLabel.setText("Ready to monitor: " + file.getName());
            refreshLiveLogs();
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

    private void startMonitoring() {
        if (monitoredFile == null) {
            showError("Please choose a log file to monitor first.");
            return;
        }

        if (!monitoredFile.isFile() || !monitoredFile.canRead()) {
            showError("Selected monitor file cannot be read.");
            return;
        }

        stopMonitoring();

        try {
            watchService = FileSystems.getDefault().newWatchService();
            Path parent = monitoredFile.toPath().getParent();
            if (parent == null) {
                showError("Selected monitor file has no parent folder.");
                return;
            }

            parent.register(
                    watchService,
                    StandardWatchEventKinds.ENTRY_CREATE,
                    StandardWatchEventKinds.ENTRY_MODIFY
            );

            startMonitorButton.setDisable(true);
            stopMonitorButton.setDisable(false);
            monitorStatusLabel.setText("Monitoring: " + monitoredFile.getName());

            monitorThread = new Thread(() -> watchMonitorFile(parent), "log-file-monitor");
            monitorThread.setDaemon(true);
            monitorThread.start();

            analyzeMonitoredFile("Initial monitor analysis completed.");
        } catch (IOException e) {
            showError("Unable to start monitor: " + e.getMessage());
            stopMonitoring();
        }
    }

    private void watchMonitorFile(Path parent) {
        while (watchService != null) {
            try {
                WatchKey key = watchService.take();
                for (WatchEvent<?> event : key.pollEvents()) {
                    if (event.kind() == StandardWatchEventKinds.OVERFLOW) {
                        continue;
                    }

                    Path changedPath = parent.resolve((Path) event.context());
                    if (changedPath.equals(monitoredFile.toPath())) {
                        scheduleMonitoredAnalysis();
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
                    monitorStatusLabel.setText("Monitor stopped.");
                    showError("Monitor failed: " + e.getMessage());
                });
                break;
            }
        }
    }

    private void scheduleMonitoredAnalysis() {
        if (pendingMonitorAnalysis != null) {
            pendingMonitorAnalysis.cancel(false);
        }

        pendingMonitorAnalysis = monitorDebouncer.schedule(
                () -> Platform.runLater(() -> analyzeMonitoredFile("Monitor analysis completed after file change.")),
                2,
                TimeUnit.SECONDS
        );
    }

    private void analyzeMonitoredFile(String successMessage) {
        if (monitoredFile == null || !monitorAnalysisRunning.compareAndSet(false, true)) {
            return;
        }

        Task<AnalysisResult> task = new Task<>() {
            @Override
            protected AnalysisResult call() throws Exception {
                return clientService.analyzeFile(monitoredFile);
            }
        };

        progressIndicator.visibleProperty().unbind();
        progressIndicator.visibleProperty().bind(task.runningProperty());
        monitorStatusLabel.setText("Analyzing monitored file...");

        task.setOnSucceeded(e -> {
            monitorAnalysisRunning.set(false);
            AnalysisResult result = task.getValue();
            updateDashboard(result);
            refreshLiveLogs();
            loadHistory();
            monitorStatusLabel.setText("Monitoring: " + monitoredFile.getName());
            statusLabel.setText(successMessage);
        });

        task.setOnFailed(e -> {
            monitorAnalysisRunning.set(false);
            Throwable ex = task.getException();
            monitorStatusLabel.setText("Monitoring: " + monitoredFile.getName());
            showError(ex == null ? "Monitor analysis failed." : ex.getMessage());
        });

        Thread thread = new Thread(task, "monitored-log-analysis");
        thread.setDaemon(true);
        thread.start();
    }

    private void stopMonitoring() {
        if (pendingMonitorAnalysis != null) {
            pendingMonitorAnalysis.cancel(false);
            pendingMonitorAnalysis = null;
        }

        if (watchService != null) {
            try {
                watchService.close();
            } catch (IOException ignored) {
                // Monitor is already stopping.
            }
            watchService = null;
        }

        if (monitorThread != null) {
            monitorThread.interrupt();
            monitorThread = null;
        }

        if (startMonitorButton != null) {
            startMonitorButton.setDisable(false);
        }
        if (stopMonitorButton != null) {
            stopMonitorButton.setDisable(true);
        }
        if (monitorStatusLabel != null) {
            monitorStatusLabel.setText("Monitor stopped.");
        }
    }

    private void startPacketCapture() {
        String networkInterface = captureInterfaceField.getText().trim();
        if (networkInterface.isBlank()) {
            showError("Please enter a network interface, such as en0.");
            return;
        }

        stopPacketCapture();
        capturedEntries.clear();
        setLiveRows(List.of());

        try {
            ProcessBuilder builder = new ProcessBuilder(
                    "tcpdump",
                    "-l",
                    "-n",
                    "-i",
                    networkInterface,
                    "ip"
            );
            builder.redirectErrorStream(true);
            captureProcess = builder.start();
            startCaptureButton.setDisable(true);
            stopCaptureButton.setDisable(false);
            captureStatusLabel.setText("Capturing on " + networkInterface + "...");

            captureThread = new Thread(() -> readPacketCaptureOutput(networkInterface), "tcpdump-capture-reader");
            captureThread.setDaemon(true);
            captureThread.start();
        } catch (IOException e) {
            stopPacketCapture();
            showError("Unable to start tcpdump. On macOS this may require running Eclipse with packet capture permission. "
                    + e.getMessage());
        }
    }

    private void readPacketCaptureOutput(String networkInterface) {
        TcpdumpPacketParser parser = new TcpdumpPacketParser();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                captureProcess.getInputStream(),
                StandardCharsets.UTF_8
        ))) {
            String line;
            while ((line = reader.readLine()) != null && captureProcess != null) {
                String outputLine = line;
                parser.parse(outputLine).ifPresent(entry -> {
                    capturedEntries.add(entry);
                    Platform.runLater(() -> {
                        setLiveRows(List.copyOf(capturedEntries));
                        captureStatusLabel.setText("Capturing on " + networkInterface
                                + " (" + capturedEntries.size() + " packets)");
                    });
                    scheduleCaptureAnalysis();
                });

                if (outputLine.toLowerCase().contains("permission denied")
                        || outputLine.toLowerCase().contains("you don't have permission")) {
                    Platform.runLater(() -> showError(outputLine));
                }
            }
        } catch (IOException e) {
            if (captureProcess != null) {
                Platform.runLater(() -> showError("Packet capture stopped: " + e.getMessage()));
            }
        } finally {
            Platform.runLater(this::stopPacketCapture);
        }
    }

    private void scheduleCaptureAnalysis() {
        if (pendingCaptureAnalysis != null) {
            pendingCaptureAnalysis.cancel(false);
        }

        pendingCaptureAnalysis = monitorDebouncer.schedule(
                () -> Platform.runLater(this::analyzeCapturedPackets),
                3,
                TimeUnit.SECONDS
        );
    }

    private void analyzeCapturedPackets() {
        List<LogEntry> snapshot = List.copyOf(capturedEntries);
        if (snapshot.isEmpty() || !captureAnalysisRunning.compareAndSet(false, true)) {
            return;
        }

        Task<AnalysisResult> task = new Task<>() {
            @Override
            protected AnalysisResult call() throws Exception {
                return clientService.analyzeCsvContent("tcpdump-live-capture.csv", toCsv(snapshot));
            }
        };

        progressIndicator.visibleProperty().unbind();
        progressIndicator.visibleProperty().bind(task.runningProperty());

        task.setOnSucceeded(e -> {
            captureAnalysisRunning.set(false);
            updateDashboard(task.getValue());
            loadHistory();
            statusLabel.setText("Live packet capture analysis completed.");
        });

        task.setOnFailed(e -> {
            captureAnalysisRunning.set(false);
            Throwable ex = task.getException();
            showError(ex == null ? "Live packet capture analysis failed." : ex.getMessage());
        });

        Thread thread = new Thread(task, "packet-capture-analysis");
        thread.setDaemon(true);
        thread.start();
    }

    private void stopPacketCapture() {
        if (pendingCaptureAnalysis != null) {
            pendingCaptureAnalysis.cancel(false);
            pendingCaptureAnalysis = null;
        }

        if (captureProcess != null) {
            captureProcess.destroy();
            captureProcess = null;
        }

        if (captureThread != null) {
            captureThread.interrupt();
            captureThread = null;
        }

        if (startCaptureButton != null) {
            startCaptureButton.setDisable(false);
        }
        if (stopCaptureButton != null) {
            stopCaptureButton.setDisable(true);
        }
        if (captureStatusLabel != null) {
            captureStatusLabel.setText("Packet capture stopped.");
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

    private void refreshLiveLogs() {
        if (monitoredFile == null || liveLogTable == null) {
            return;
        }

        Task<List<LogEntry>> task = new Task<>() {
            @Override
            protected List<LogEntry> call() throws Exception {
                String csvContent = Files.readString(monitoredFile.toPath(), StandardCharsets.UTF_8);
                return new CsvLogParser().parse(csvContent);
            }
        };

        task.setOnSucceeded(e -> {
            List<LogEntry> entries = task.getValue();
            setLiveRows(entries);
        });

        task.setOnFailed(e -> {
            Throwable ex = task.getException();
            liveLogCountLabel.setText("Live Rows: unavailable");
            showError(ex == null ? "Unable to load live logs." : ex.getMessage());
        });

        Thread thread = new Thread(task, "live-log-table-refresh");
        thread.setDaemon(true);
        thread.start();
    }

    private void setLiveRows(List<LogEntry> entries) {
        liveLogTable.getItems().setAll(entries);
        liveLogCountLabel.setText("Live Rows: " + entries.size());
        if (!entries.isEmpty()) {
            liveLogTable.scrollTo(entries.size() - 1);
        }
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
        stopMonitoring();
        stopPacketCapture();
        monitorDebouncer.shutdownNow();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
