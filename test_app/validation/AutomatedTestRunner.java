package validation;

import java.io.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 * Complete automation framework for PathSentinel ground truth validation.
 * Orchestrates the entire validation pipeline from APK building to report generation.
 */
public class AutomatedTestRunner {
    
    private static final String VALIDATION_BASE_DIR = "/home/eddy/Research/tiro/static/test_app/validation";
    private static final String REPORTS_DIR = VALIDATION_BASE_DIR + "/reports";
    private static final String GROUND_TRUTH_DIR = VALIDATION_BASE_DIR + "/ground_truth";
    
    private GroundTruthLoader groundTruthLoader;
    private PathSentinelAnalysisRunner analysisRunner;
    private GroundTruthValidator validator;
    private ValidationReport finalReport;
    
    public AutomatedTestRunner() {
        this.groundTruthLoader = new GroundTruthLoader();
        this.analysisRunner = new PathSentinelAnalysisRunner();
        this.validator = new GroundTruthValidator();
    }
    
    /**
     * Main entry point for automated testing
     */
    public static void main(String[] args) {
        System.out.println("=== PathSentinel Ground Truth Validation Framework ===");
        System.out.println("Starting automated validation pipeline...\n");
        
        AutomatedTestRunner runner = new AutomatedTestRunner();
        int exitCode = 0;
        
        try {
            // Run complete validation pipeline
            boolean success = runner.runCompleteValidationPipeline();
            
            if (!success) {
                System.err.println("\nValidation pipeline completed with failures!");
                exitCode = 1;
            } else {
                System.out.println("\nValidation pipeline completed successfully!");
                exitCode = 0;
            }
            
            // Print summary
            runner.printValidationSummary();
            
        } catch (Exception e) {
            System.err.println("\nFatal error in validation pipeline: " + e.getMessage());
            e.printStackTrace();
            exitCode = 2;
        }
        
        System.exit(exitCode);
    }
    
    /**
     * Runs the complete validation pipeline
     */
    public boolean runCompleteValidationPipeline() throws Exception {
        System.out.println("Phase 1: Building comprehensive test APK...");
        boolean apkBuilt = buildComprehensiveTestApp();
        if (!apkBuilt) {
            System.err.println("Failed to build test APK");
            return false;
        }
        System.out.println("✓ Test APK built successfully\n");
        
        System.out.println("Phase 2: Loading ground truth expectations...");
        Map<String, GroundTruthExpectation> expectations = loadAllExpectations();
        System.out.printf("✓ Loaded %d ground truth expectations\n\n", expectations.size());
        
        System.out.println("Phase 3: Running PathSentinel analysis...");
        Map<String, PathSentinelResult> results = runPathSentinelAnalysis();
        System.out.printf("✓ PathSentinel analysis completed with %d results\n\n", results.size());
        
        System.out.println("Phase 4: Validating results against ground truth...");
        ValidationReport report = validateAllResults(expectations, results);
        System.out.printf("✓ Validation completed: %d/%d tests passed\n\n", 
                report.overallStats.passedTests, report.overallStats.totalTests);
        
        System.out.println("Phase 5: Generating comprehensive reports...");
        generateAllReports(report);
        System.out.println("✓ Reports generated successfully\n");
        
        this.finalReport = report;
        
        // Determine overall success
        boolean hasFailures = report.overallStats.criticalFailTests > 0 || 
                             report.overallStats.failedTests > (report.overallStats.totalTests * 0.2); // >20% fail rate
        
        return !hasFailures;
    }
    
    /**
     * Builds the comprehensive test APK with all test phases
     */
    private boolean buildComprehensiveTestApp() throws Exception {
        System.out.println("Building test APK using Gradle...");
        
        // Execute Gradle build
        ProcessBuilder pb = new ProcessBuilder(
                "./gradlew", "assembleDebug", "--stacktrace"
        );
        pb.directory(new File("/home/eddy/Research/tiro/static/test_app"));
        pb.redirectErrorStream(true);
        
        Process process = pb.start();
        
        // Capture build output
        StringBuilder buildOutput = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                buildOutput.append(line).append("\n");
                if (line.contains("BUILD SUCCESSFUL") || line.contains("BUILD FAILED") || 
                    line.contains("FAILURE") || line.contains("ERROR")) {
                    System.out.println("Gradle: " + line);
                }
            }
        }
        
        int exitCode = process.waitFor();
        
        if (exitCode != 0) {
            System.err.println("Gradle build failed with exit code: " + exitCode);
            System.err.println("Build output:\n" + buildOutput.toString());
            return false;
        }
        
        // Verify APK was created
        String apkPath = "/home/eddy/Research/tiro/static/test_app/app/build/outputs/apk/debug/app-debug.apk";
        if (!Files.exists(Paths.get(apkPath))) {
            System.err.println("APK not found at expected location: " + apkPath);
            return false;
        }
        
        // Copy APK to expected location for PathSentinel
        String targetApkPath = "/home/eddy/Research/tiro/static/test_app/constraint_validation_test_app.apk";
        Files.copy(Paths.get(apkPath), Paths.get(targetApkPath), StandardCopyOption.REPLACE_EXISTING);
        
        System.out.println("Test APK built and copied to: " + targetApkPath);
        return true;
    }
    
    /**
     * Loads all ground truth expectations from JSON files
     */
    private Map<String, GroundTruthExpectation> loadAllExpectations() throws Exception {
        Map<String, GroundTruthExpectation> allExpectations = new HashMap<>();
        
        // Load each phase's expectations
        allExpectations.putAll(groundTruthLoader.loadHijackingExpectations());
        allExpectations.putAll(groundTruthLoader.loadTraversalExpectations());
        allExpectations.putAll(groundTruthLoader.loadStringConstructionExpectations());
        allExpectations.putAll(groundTruthLoader.loadConstraintValidationExpectations());
        
        return allExpectations;
    }
    
    /**
     * Runs PathSentinel analysis on the test APK
     */
    private Map<String, PathSentinelResult> runPathSentinelAnalysis() throws Exception {
        return analysisRunner.runFullAnalysis();
    }
    
    /**
     * Validates all results against ground truth expectations
     */
    private ValidationReport validateAllResults(
            Map<String, GroundTruthExpectation> expectations,
            Map<String, PathSentinelResult> actualResults) throws Exception {
        
        ValidationReport report = GroundTruthValidator.generateComprehensiveReport(expectations, actualResults);
        
        // Add metadata
        report.timestamp = LocalDateTime.now();
        report.pathSentinelVersion = analysisRunner.getPathSentinelVersion();
        report.testSuiteVersion = "1.0";
        
        return report;
    }
    
    /**
     * Generates all validation reports (HTML, JSON, text)
     */
    private void generateAllReports(ValidationReport report) throws Exception {
        // Create reports directory
        Files.createDirectories(Paths.get(REPORTS_DIR));
        
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        
        // Generate HTML report
        String htmlReport = report.generateHTMLReport();
        String htmlPath = REPORTS_DIR + "/validation_report_" + timestamp + ".html";
        Files.write(Paths.get(htmlPath), htmlReport.getBytes());
        System.out.println("HTML report generated: " + htmlPath);
        
        // Generate JSON report
        String jsonReport = report.generateJSONReport();
        String jsonPath = REPORTS_DIR + "/validation_report_" + timestamp + ".json";
        Files.write(Paths.get(jsonPath), jsonReport.getBytes());
        System.out.println("JSON report generated: " + jsonPath);
        
        // Generate detailed text report
        String textReport = generateDetailedTextReport(report);
        String textPath = REPORTS_DIR + "/validation_report_" + timestamp + ".txt";
        Files.write(Paths.get(textPath), textReport.getBytes());
        System.out.println("Text report generated: " + textPath);
        
        // Generate latest report links (overwrite)
        Files.copy(Paths.get(htmlPath), Paths.get(REPORTS_DIR + "/latest_validation_report.html"), 
                StandardCopyOption.REPLACE_EXISTING);
        Files.copy(Paths.get(jsonPath), Paths.get(REPORTS_DIR + "/latest_validation_report.json"), 
                StandardCopyOption.REPLACE_EXISTING);
        Files.copy(Paths.get(textPath), Paths.get(REPORTS_DIR + "/latest_validation_report.txt"), 
                StandardCopyOption.REPLACE_EXISTING);
    }
    
    /**
     * Generates detailed text report for console/email consumption
     */
    private String generateDetailedTextReport(ValidationReport report) {
        StringBuilder text = new StringBuilder();
        
        text.append("=== PathSentinel Ground Truth Validation Report ===\n\n");
        text.append(String.format("Generated: %s\n", 
                report.timestamp.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))));
        text.append(String.format("PathSentinel Version: %s\n", report.pathSentinelVersion));
        text.append(String.format("Test Suite Version: %s\n\n", report.testSuiteVersion));
        
        // Overall results
        text.append("OVERALL RESULTS:\n");
        text.append(String.format("- Total Tests: %d\n", report.overallStats.totalTests));
        text.append(String.format("- Passed: %d (%.1f%%)\n", 
                report.overallStats.passedTests, report.overallStats.passRate * 100));
        text.append(String.format("- Partial Pass: %d (%.1f%%)\n", 
                report.overallStats.partialPassTests, report.overallStats.partialPassRate * 100));
        text.append(String.format("- Failed: %d (%.1f%%)\n", 
                report.overallStats.failedTests, report.overallStats.failRate * 100));
        text.append(String.format("- Critical Failures: %d (%.1f%%)\n", 
                report.overallStats.criticalFailTests, report.overallStats.criticalFailRate * 100));
        text.append(String.format("- Average Score: %.1f%%\n\n", 
                report.overallStats.averageScore * 100));
        
        // Phase results
        text.append("PHASE RESULTS:\n");
        addPhaseResults(text, "HIJACKING TESTS", report.hijackingStats);
        addPhaseResults(text, "TRAVERSAL TESTS", report.traversalStats);
        addPhaseResults(text, "STRING CONSTRUCTION TESTS", report.stringConstructionStats);
        addPhaseResults(text, "CONSTRAINT VALIDATION TESTS", report.constraintStats);
        
        // Performance metrics
        text.append("PERFORMANCE METRICS:\n");
        text.append(String.format("- Total Analysis Time: %.1f seconds\n", 
                report.totalAnalysisTimeMs / 1000.0));
        text.append(String.format("- Average Analysis Time: %.1f seconds\n", 
                report.averageAnalysisTimeMs / 1000.0));
        text.append(String.format("- Timeouts: %d\n", report.timeoutCount));
        text.append(String.format("- Errors: %d\n\n", report.errorCount));
        
        // Critical failures
        if (!report.criticalFailures.isEmpty()) {
            text.append("CRITICAL FAILURES:\n");
            for (String failure : report.criticalFailures) {
                text.append(String.format("- %s\n", failure));
            }
            text.append("\n");
        }
        
        // Recommendations
        if (!report.recommendations.isEmpty()) {
            text.append("RECOMMENDATIONS:\n");
            for (int i = 0; i < report.recommendations.size(); i++) {
                text.append(String.format("%d. %s\n", i + 1, report.recommendations.get(i)));
            }
            text.append("\n");
        }
        
        // Notable improvements
        if (!report.improvements.isEmpty()) {
            text.append("NOTABLE IMPROVEMENTS:\n");
            for (String improvement : report.improvements) {
                text.append(String.format("- %s\n", improvement));
            }
            text.append("\n");
        }
        
        return text.toString();
    }
    
    /**
     * Adds phase results to text report
     */
    private void addPhaseResults(StringBuilder text, String phaseName, ValidationStatistics stats) {
        if (stats != null) {
            text.append(String.format("%s (%d tests):\n", phaseName, stats.totalTests));
            text.append(String.format("  ✓ Passed: %d (%.1f%%)\n", 
                    stats.passedTests, stats.passRate * 100));
            text.append(String.format("  ~ Partial: %d (%.1f%%)\n", 
                    stats.partialPassTests, stats.partialPassRate * 100));
            text.append(String.format("  ✗ Failed: %d (%.1f%%)\n", 
                    stats.failedTests, stats.failRate * 100));
            if (stats.criticalFailTests > 0) {
                text.append(String.format("  ⚠ Critical: %d (%.1f%%)\n", 
                        stats.criticalFailTests, stats.criticalFailRate * 100));
            }
            text.append(String.format("  Average Score: %.1f%%\n\n", stats.averageScore * 100));
        }
    }
    
    /**
     * Prints validation summary to console
     */
    private void printValidationSummary() {
        if (finalReport == null) return;
        
        System.out.println("=== VALIDATION SUMMARY ===");
        System.out.printf("Overall Success Rate: %.1f%% (%d/%d tests passed)\n",
                finalReport.overallStats.passRate * 100,
                finalReport.overallStats.passedTests,
                finalReport.overallStats.totalTests);
        
        if (finalReport.overallStats.criticalFailTests > 0) {
            System.out.printf("⚠ CRITICAL FAILURES: %d tests failed critically\n", 
                    finalReport.overallStats.criticalFailTests);
        }
        
        if (!finalReport.recommendations.isEmpty()) {
            System.out.println("\nTop Recommendations:");
            for (int i = 0; i < Math.min(3, finalReport.recommendations.size()); i++) {
                System.out.printf("%d. %s\n", i + 1, finalReport.recommendations.get(i));
            }
        }
        
        System.out.printf("\nDetailed reports available in: %s/\n", REPORTS_DIR);
        System.out.println("Latest reports:");
        System.out.println("- HTML: " + REPORTS_DIR + "/latest_validation_report.html");
        System.out.println("- JSON: " + REPORTS_DIR + "/latest_validation_report.json");
        System.out.println("- Text: " + REPORTS_DIR + "/latest_validation_report.txt");
    }
    
    /**
     * Checks if the validation passed overall
     */
    public boolean hasValidationPassed() {
        if (finalReport == null) return false;
        
        // Pass criteria: <20% failure rate and no critical failures
        double failureRate = finalReport.overallStats.failRate;
        int criticalFailures = finalReport.overallStats.criticalFailTests;
        
        return failureRate < 0.2 && criticalFailures == 0;
    }
    
    /**
     * Gets validation statistics for CI/CD integration
     */
    public ValidationStatistics getValidationStatistics() {
        return finalReport != null ? finalReport.overallStats : null;
    }
}

/**
 * Utility class for loading ground truth expectations from JSON files
 */
class GroundTruthLoader {
    
    private static final String GROUND_TRUTH_DIR = "/home/eddy/Research/tiro/static/test_app/validation/ground_truth";
    private Gson gson;
    
    public GroundTruthLoader() {
        this.gson = new GsonBuilder().setPrettyPrinting().create();
    }
    
    public Map<String, GroundTruthExpectation> loadHijackingExpectations() throws Exception {
        return loadExpectationsFromFile("hijacking_ground_truth.json");
    }
    
    public Map<String, GroundTruthExpectation> loadTraversalExpectations() throws Exception {
        return loadExpectationsFromFile("traversal_ground_truth.json");
    }
    
    public Map<String, GroundTruthExpectation> loadStringConstructionExpectations() throws Exception {
        return loadExpectationsFromFile("string_construction_ground_truth.json");
    }
    
    public Map<String, GroundTruthExpectation> loadConstraintValidationExpectations() throws Exception {
        return loadExpectationsFromFile("constraint_validation_ground_truth.json");
    }
    
    private Map<String, GroundTruthExpectation> loadExpectationsFromFile(String filename) throws Exception {
        Path filePath = Paths.get(GROUND_TRUTH_DIR, filename);
        if (!Files.exists(filePath)) {
            throw new FileNotFoundException("Ground truth file not found: " + filePath);
        }
        
        String content = new String(Files.readAllBytes(filePath));
        
        // Parse JSON as map of test ID to expectation object
        Map<String, Map<String, Object>> rawData = gson.fromJson(content, Map.class);
        Map<String, GroundTruthExpectation> expectations = new HashMap<>();
        
        for (Map.Entry<String, Map<String, Object>> entry : rawData.entrySet()) {
            String testKey = entry.getKey();
            Map<String, Object> data = entry.getValue();
            
            GroundTruthExpectation expectation = convertToExpectation(data);
            expectations.put(testKey, expectation);
        }
        
        System.out.printf("Loaded %d expectations from %s\n", expectations.size(), filename);
        return expectations;
    }
    
    private GroundTruthExpectation convertToExpectation(Map<String, Object> data) {
        GroundTruthExpectation expectation = new GroundTruthExpectation();
        
        expectation.testId = (String) data.get("testId");
        expectation.testMethod = (String) data.get("testMethod");
        expectation.vulnerabilityType = (String) data.get("vulnerabilityType");
        expectation.pathType = (String) data.get("pathType");
        expectation.expectedPath = (String) data.get("expectedPath");
        expectation.expectedConstructionPattern = (String) data.get("expectedConstructionPattern");
        expectation.shouldResolveCompletely = (Boolean) data.getOrDefault("shouldResolveCompletely", false);
        expectation.expectedEntryPoint = (String) data.get("expectedEntryPoint");
        expectation.expectedTargetMethod = (String) data.get("expectedTargetMethod");
        expectation.isVulnerable = (Boolean) data.getOrDefault("isVulnerable", true);
        expectation.expectedConfidenceScore = ((Number) data.getOrDefault("expectedConfidenceScore", 0.5)).doubleValue();
        expectation.expectedVariableCount = ((Number) data.getOrDefault("expectedVariableCount", 0)).intValue();
        
        // Convert lists
        expectation.expectedConstraints = (List<String>) data.getOrDefault("expectedConstraints", new ArrayList<>());
        expectation.expectedExternalInputs = (List<String>) data.getOrDefault("expectedExternalInputs", new ArrayList<>());
        expectation.expectedObfuscationTechniques = (List<String>) data.getOrDefault("expectedObfuscationTechniques", new ArrayList<>());
        
        return expectation;
    }
}