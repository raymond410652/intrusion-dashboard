package edu.project.intrusion.server;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import edu.project.intrusion.model.AnalysisResult;
import edu.project.intrusion.net.ClientService;

public class ConcurrentClientSmokeTest {

    private static final int DEFAULT_CLIENTS = 5;

    public static void main(String[] args) throws Exception {
        int clientCount = args.length > 0 ? Integer.parseInt(args[0]) : DEFAULT_CLIENTS;
        File testFile = createTestCsv();
        ClientService clientService = new ClientService("localhost", 5060);

        ExecutorService pool = Executors.newFixedThreadPool(clientCount);
        List<Callable<String>> tasks = new ArrayList<>();

        for (int i = 1; i <= clientCount; i++) {
            int clientNumber = i;
            tasks.add(() -> {
                AnalysisResult result = clientService.analyzeFile(testFile);
                return "client-" + clientNumber + " records=" + result.totalRecords()
                        + " alerts=" + result.alerts().size();
            });
        }

        try {
            List<Future<String>> futures = pool.invokeAll(tasks);
            for (Future<String> future : futures) {
                System.out.println(future.get());
            }
            System.out.println("Concurrent client smoke test completed for " + clientCount + " clients.");
        } finally {
            pool.shutdownNow();
            Files.deleteIfExists(testFile.toPath());
        }
    }

    private static File createTestCsv() throws Exception {
        StringBuilder csv = new StringBuilder();
        csv.append("timestamp,sourceIp,destinationIp,sourcePort,destinationPort,protocol,statusCode,dataSize\n");

        for (int i = 0; i < 25; i++) {
            csv.append("2026-04-22T10:")
                    .append(String.format("%02d", i))
                    .append(":00,192.168.1.")
                    .append(i < 10 ? 20 : 30)
                    .append(",10.0.0.5,")
                    .append(5000 + i)
                    .append(",")
                    .append(20 + i)
                    .append(",TCP,")
                    .append(i < 6 ? 404 : 200)
                    .append(",")
                    .append(1000 + i)
                    .append("\n");
        }

        File file = File.createTempFile("intrusion-concurrent-smoke-", ".csv");
        Files.writeString(file.toPath(), csv.toString(), StandardCharsets.UTF_8);
        return file;
    }
}
