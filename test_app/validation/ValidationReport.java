package validation;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Comprehensive validation report that aggregates results from all test phases
 * and provides detailed analysis of PathSentinel's performance against ground truth.
 */
public class ValidationReport {
    
    public LocalDateTime timestamp;
    public String pathSentinelVersion;
    public String testSuiteVersion;
    
    // Results by phase
    public List<ValidationResult> hijackingResults;
    public List<ValidationResult> traversalResults;
    public List<ValidationResult> stringConstructionResults;
    public List<ValidationResult> constraintResults;
    
    // Overall statistics
    public ValidationStatistics overallStats;
    public ValidationStatistics hijackingStats;
    public ValidationStatistics traversalStats;
    public ValidationStatistics stringConstructionStats;
    public ValidationStatistics constraintStats;
    
    // Performance metrics
    public long totalAnalysisTimeMs;
    public int timeoutCount;
    public int errorCount;
    public double averageAnalysisTimeMs;
    
    // Key findings
    public List<String> criticalFailures;
    public List<String> improvements;
    public List<String> recommendations;
    
    public ValidationReport() {
        this.timestamp = LocalDateTime.now();
        this.hijackingResults = new ArrayList<>();
        this.traversalResults = new ArrayList<>();
        this.stringConstructionResults = new ArrayList<>();
        this.constraintResults = new ArrayList<>();
        this.criticalFailures = new ArrayList<>();
        this.improvements = new ArrayList<>();
        this.recommendations = new ArrayList<>();
    }
    
    /**
     * Calculates comprehensive statistics across all phases
     */
    public void calculateOverallStatistics() {
        List<ValidationResult> allResults = new ArrayList<>();
        allResults.addAll(hijackingResults);
        allResults.addAll(traversalResults);
        allResults.addAll(stringConstructionResults);
        allResults.addAll(constraintResults);
        
        overallStats = calculateStats("Overall", allResults);
        hijackingStats = calculateStats("Hijacking", hijackingResults);
        traversalStats = calculateStats("Traversal", traversalResults);
        stringConstructionStats = calculateStats("String Construction", stringConstructionResults);
        constraintStats = calculateStats("Constraint Validation", constraintResults);
        
        calculatePerformanceMetrics(allResults);
        extractKeyFindings(allResults);
    }
    
    /**
     * Calculates statistics for a specific phase
     */
    private ValidationStatistics calculateStats(String phaseName, List<ValidationResult> results) {
        ValidationStatistics stats = new ValidationStatistics();
        stats.phaseName = phaseName;
        stats.totalTests = results.size();
        
        if (stats.totalTests == 0) return stats;
        
        stats.passedTests = (int) results.stream().filter(r -> r.status == ValidationResult.ValidationStatus.PASS).count();
        stats.partialPassTests = (int) results.stream().filter(r -> r.status == ValidationResult.ValidationStatus.PARTIAL_PASS).count();
        stats.failedTests = (int) results.stream().filter(r -> r.status == ValidationResult.ValidationStatus.FAIL).count();
        stats.errorTests = (int) results.stream().filter(r -> r.status == ValidationResult.ValidationStatus.ERROR).count();
        stats.criticalFailTests = (int) results.stream().filter(r -> r.status == ValidationResult.ValidationStatus.CRITICAL_FAIL).count();
        
        stats.passRate = (double) stats.passedTests / stats.totalTests;
        stats.partialPassRate = (double) stats.partialPassTests / stats.totalTests;
        stats.failRate = (double) stats.failedTests / stats.totalTests;
        stats.errorRate = (double) stats.errorTests / stats.totalTests;
        stats.criticalFailRate = (double) stats.criticalFailTests / stats.totalTests;
        
        stats.averageScore = results.stream().mapToDouble(r -> r.validationScore).average().orElse(0.0);
        
        return stats;
    }
    
    /**
     * Calculates performance metrics
     */
    private void calculatePerformanceMetrics(List<ValidationResult> allResults) {
        totalAnalysisTimeMs = allResults.stream()
                .filter(r -> r.actual != null)
                .mapToLong(r -> r.actual.analysisTimeMs)
                .sum();
        
        timeoutCount = (int) allResults.stream()
                .filter(r -> r.actual != null && r.actual.timedOut)
                .count();
        
        errorCount = (int) allResults.stream()
                .filter(r -> r.actual != null && r.actual.hasErrors)
                .count();
        
        averageAnalysisTimeMs = allResults.stream()
                .filter(r -> r.actual != null)
                .mapToLong(r -> r.actual.analysisTimeMs)
                .average()
                .orElse(0.0);
    }
    
    /**
     * Extracts key findings from validation results
     */
    private void extractKeyFindings(List<ValidationResult> allResults) {
        // Collect critical failures
        criticalFailures = allResults.stream()
                .filter(r -> r.isCritical())
                .map(r -> String.format("%s: %s", r.testId, r.validationNotes))
                .collect(Collectors.toList());
        
        // Identify improvements (high scores)
        improvements = allResults.stream()
                .filter(r -> r.validationScore >= 0.9)
                .map(r -> String.format("%s: Excellent performance (%.1f%%)", r.testId, r.validationScore * 100))
                .collect(Collectors.toList());
        
        // Generate recommendations based on common failures
        generateRecommendations(allResults);
    }
    
    /**
     * Generates recommendations based on failure patterns
     */
    private void generateRecommendations(List<ValidationResult> allResults) {
        Map<String, Integer> failurePatterns = new HashMap<>();
        
        for (ValidationResult result : allResults) {
            if (result.findings != null) {
                for (ValidationFinding finding : result.findings) {
                    if (!finding.passed) {
                        failurePatterns.merge(finding.aspect, 1, Integer::sum);
                    }
                }
            }
        }
        
        // Generate recommendations based on most common failures
        failurePatterns.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .limit(5)
                .forEach(entry -> {
                    String recommendation = generateRecommendationForAspect(entry.getKey(), entry.getValue());
                    if (recommendation != null) {
                        recommendations.add(recommendation);
                    }
                });
    }
    
    /**
     * Generates specific recommendations for failure aspects
     */
    private String generateRecommendationForAspect(String aspect, int failureCount) {
        switch (aspect) {
            case "path_resolution":
                return String.format("Fix path resolution issues (%d failures) - improve FilePathResolver.java", failureCount);
            case "constraint_generation":
                return String.format("Enhance constraint collection (%d failures) - review ConstraintAnalysis.java", failureCount);
            case "vulnerability_type":
                return String.format("Improve vulnerability classification (%d failures) - update detection logic", failureCount);
            case "external_inputs":
                return String.format("Enhance external input detection (%d failures) - expand input source recognition", failureCount);
            case "construction_pattern":
                return String.format("Improve construction pattern detection (%d failures) - enhance StringBuilder handling", failureCount);
            default:
                return null;
        }
    }
    
    /**
     * Generates HTML report
     */
    public String generateHTMLReport() {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n<html>\n<head>\n");
        html.append("<title>PathSentinel Ground Truth Validation Report</title>\n");
        html.append("<style>\n");
        html.append("body { font-family: Arial, sans-serif; margin: 20px; }\n");
        html.append(".header { background-color: #f5f5f5; padding: 20px; border-radius: 5px; }\n");
        html.append(".stats { display: flex; gap: 20px; margin: 20px 0; }\n");
        html.append(".stat-box { border: 1px solid #ddd; padding: 15px; border-radius: 5px; flex: 1; }\n");
        html.append(".pass { color: #28a745; }\n");
        html.append(".fail { color: #dc3545; }\n");
        html.append(".partial { color: #ffc107; }\n");
        html.append(".error { color: #6c757d; }\n");
        html.append(".critical { color: #dc3545; font-weight: bold; }\n");
        html.append("table { border-collapse: collapse; width: 100%; margin: 20px 0; }\n");
        html.append("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n");
        html.append("th { background-color: #f2f2f2; }\n");
        html.append("</style>\n</head>\n<body>\n");
        
        // Header
        html.append("<div class='header'>\n");
        html.append("<h1>PathSentinel Ground Truth Validation Report</h1>\n");
        html.append(String.format("<p>Generated: %s</p>\n", timestamp.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))));
        html.append(String.format("<p>PathSentinel Version: %s</p>\n", pathSentinelVersion != null ? pathSentinelVersion : "Unknown"));
        html.append(String.format("<p>Test Suite Version: %s</p>\n", testSuiteVersion != null ? testSuiteVersion : "1.0"));
        html.append("</div>\n");
        
        // Overall Statistics
        html.append("<h2>Overall Results</h2>\n");
        if (overallStats != null) {
            html.append(generateStatsHTML(overallStats));
        }
        
        // Phase-specific Results
        html.append("<h2>Phase Results</h2>\n");
        html.append("<div class='stats'>\n");
        if (hijackingStats != null) html.append(generatePhaseStatsHTML(hijackingStats));
        if (traversalStats != null) html.append(generatePhaseStatsHTML(traversalStats));
        if (stringConstructionStats != null) html.append(generatePhaseStatsHTML(stringConstructionStats));
        if (constraintStats != null) html.append(generatePhaseStatsHTML(constraintStats));
        html.append("</div>\n");
        
        // Detailed Results Table
        html.append("<h2>Detailed Test Results</h2>\n");
        html.append(generateDetailedResultsTable());
        
        // Performance Metrics
        html.append("<h2>Performance Metrics</h2>\n");
        html.append(generatePerformanceHTML());
        
        // Key Findings
        html.append("<h2>Key Findings</h2>\n");
        html.append(generateFindingsHTML());
        
        // Recommendations
        html.append("<h2>Recommendations</h2>\n");
        html.append(generateRecommendationsHTML());
        
        html.append("</body>\n</html>");
        return html.toString();
    }
    
    private String generateStatsHTML(ValidationStatistics stats) {
        return String.format(
                "<div class='stat-box'>" +
                "<h3>%s</h3>" +
                "<p>Total Tests: %d</p>" +
                "<p class='pass'>Passed: %d (%.1f%%)</p>" +
                "<p class='partial'>Partial Pass: %d (%.1f%%)</p>" +
                "<p class='fail'>Failed: %d (%.1f%%)</p>" +
                "<p class='error'>Errors: %d (%.1f%%)</p>" +
                "<p class='critical'>Critical: %d (%.1f%%)</p>" +
                "<p>Average Score: %.1f%%</p>" +
                "</div>",
                stats.phaseName, stats.totalTests,
                stats.passedTests, stats.passRate * 100,
                stats.partialPassTests, stats.partialPassRate * 100,
                stats.failedTests, stats.failRate * 100,
                stats.errorTests, stats.errorRate * 100,
                stats.criticalFailTests, stats.criticalFailRate * 100,
                stats.averageScore * 100);
    }
    
    private String generatePhaseStatsHTML(ValidationStatistics stats) {
        return String.format(
                "<div class='stat-box'>" +
                "<h4>%s</h4>" +
                "<p>Pass: %d/%d</p>" +
                "<p>Score: %.1f%%</p>" +
                "</div>",
                stats.phaseName, stats.passedTests, stats.totalTests, stats.averageScore * 100);
    }
    
    private String generateDetailedResultsTable() {
        StringBuilder table = new StringBuilder();
        table.append("<table>\n<tr><th>Test ID</th><th>Phase</th><th>Status</th><th>Score</th><th>Expected Path</th><th>Actual Path</th><th>Notes</th></tr>\n");
        
        List<ValidationResult> allResults = new ArrayList<>();
        allResults.addAll(hijackingResults);
        allResults.addAll(traversalResults);
        allResults.addAll(stringConstructionResults);
        allResults.addAll(constraintResults);
        
        for (ValidationResult result : allResults) {
            String phase = result.testId.startsWith("H") ? "Hijacking" :
                          result.testId.startsWith("T") ? "Traversal" :
                          result.testId.startsWith("S") ? "String Construction" : "Constraint";
            
            String statusClass = result.status == ValidationResult.ValidationStatus.PASS ? "pass" :
                                result.status == ValidationResult.ValidationStatus.PARTIAL_PASS ? "partial" :
                                result.status == ValidationResult.ValidationStatus.CRITICAL_FAIL ? "critical" : "fail";
            
            table.append(String.format(
                    "<tr><td>%s</td><td>%s</td><td class='%s'>%s</td><td>%.1f%%</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
                    result.testId, phase, statusClass, result.status.name(), result.validationScore * 100,
                    result.expected != null ? result.expected.expectedPath : "N/A",
                    result.actual != null ? result.actual.actualPath : "N/A",
                    result.validationNotes != null ? result.validationNotes : ""));
        }
        
        table.append("</table>\n");
        return table.toString();
    }
    
    private String generatePerformanceHTML() {
        return String.format(
                "<div class='stat-box'>" +
                "<p>Total Analysis Time: %.1f seconds</p>" +
                "<p>Average Analysis Time: %.1f seconds</p>" +
                "<p>Timeouts: %d</p>" +
                "<p>Errors: %d</p>" +
                "</div>",
                totalAnalysisTimeMs / 1000.0, averageAnalysisTimeMs / 1000.0, timeoutCount, errorCount);
    }
    
    private String generateFindingsHTML() {
        StringBuilder html = new StringBuilder();
        
        if (!criticalFailures.isEmpty()) {
            html.append("<h3 class='critical'>Critical Failures</h3><ul>");
            for (String failure : criticalFailures) {
                html.append(String.format("<li class='critical'>%s</li>", failure));
            }
            html.append("</ul>");
        }
        
        if (!improvements.isEmpty()) {
            html.append("<h3 class='pass'>Notable Improvements</h3><ul>");
            for (String improvement : improvements) {
                html.append(String.format("<li class='pass'>%s</li>", improvement));
            }
            html.append("</ul>");
        }
        
        return html.toString();
    }
    
    private String generateRecommendationsHTML() {
        StringBuilder html = new StringBuilder();
        html.append("<ol>");
        for (String recommendation : recommendations) {
            html.append(String.format("<li>%s</li>", recommendation));
        }
        html.append("</ol>");
        return html.toString();
    }
    
    /**
     * Generates JSON report for programmatic consumption
     */
    public String generateJSONReport() {
        // Simple JSON generation - could be enhanced with a proper JSON library
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append(String.format("  \"timestamp\": \"%s\",\n", timestamp));
        json.append(String.format("  \"pathSentinelVersion\": \"%s\",\n", pathSentinelVersion != null ? pathSentinelVersion : "Unknown"));
        json.append(String.format("  \"testSuiteVersion\": \"%s\",\n", testSuiteVersion != null ? testSuiteVersion : "1.0"));
        
        if (overallStats != null) {
            json.append("  \"overallStats\": {\n");
            json.append(String.format("    \"totalTests\": %d,\n", overallStats.totalTests));
            json.append(String.format("    \"passedTests\": %d,\n", overallStats.passedTests));
            json.append(String.format("    \"passRate\": %.3f,\n", overallStats.passRate));
            json.append(String.format("    \"averageScore\": %.3f\n", overallStats.averageScore));
            json.append("  },\n");
        }
        
        json.append("  \"performance\": {\n");
        json.append(String.format("    \"totalAnalysisTimeMs\": %d,\n", totalAnalysisTimeMs));
        json.append(String.format("    \"averageAnalysisTimeMs\": %.1f,\n", averageAnalysisTimeMs));
        json.append(String.format("    \"timeoutCount\": %d,\n", timeoutCount));
        json.append(String.format("    \"errorCount\": %d\n", errorCount));
        json.append("  }\n");
        
        json.append("}");
        return json.toString();
    }
}

/**
 * Statistics for a specific validation phase
 */
class ValidationStatistics {
    public String phaseName;
    public int totalTests;
    public int passedTests;
    public int partialPassTests;
    public int failedTests;
    public int errorTests;
    public int criticalFailTests;
    
    public double passRate;
    public double partialPassRate;
    public double failRate;
    public double errorRate;
    public double criticalFailRate;
    
    public double averageScore;
}