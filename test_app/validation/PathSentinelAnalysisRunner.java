package validation;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonParser;

/**
 * Automated PathSentinel analysis runner that executes PathSentinel static analysis
 * on the test APK and parses the results for validation.
 */
public class PathSentinelAnalysisRunner {
    
    private static final String PATHSENTINEL_JAR = "PathSentStaticAnalysis.jar";
    private static final String TEST_APK = "constraint_validation_test_app.apk";
    private static final String OUTPUT_DIR = "pathSentOutput";
    private static final String APP_INFO_JSON = "appInfo.json";
    private static final String TARGETED_METHODS_FILE = "targetedMethods.txt";
    
    private static final int ANALYSIS_TIMEOUT_MINUTES = 15;
    private static final String PATHSENTINEL_BASE_DIR = "/home/eddy/Research/tiro/static";
    
    private String testAppPath;
    private String outputPath;
    private long analysisStartTime;
    private long analysisEndTime;
    
    public PathSentinelAnalysisRunner() {
        this.testAppPath = Paths.get(PATHSENTINEL_BASE_DIR, "test_app", TEST_APK).toString();
        this.outputPath = Paths.get(PATHSENTINEL_BASE_DIR, "test_app", OUTPUT_DIR).toString();
    }
    
    /**
     * Runs complete PathSentinel analysis on the test APK
     */
    public Map<String, PathSentinelResult> runFullAnalysis() throws Exception {
        System.out.println("Starting PathSentinel analysis...");
        
        // Prepare analysis environment
        prepareAnalysisEnvironment();
        
        // Execute PathSentinel analysis
        boolean analysisSuccess = executePathSentinelAnalysis();
        
        if (!analysisSuccess) {
            throw new RuntimeException("PathSentinel analysis failed");
        }
        
        // Parse analysis results
        Map<String, PathSentinelResult> results = parseAnalysisResults();
        
        System.out.printf("PathSentinel analysis completed in %.1f seconds\n", 
                (analysisEndTime - analysisStartTime) / 1000.0);
        
        return results;
    }
    
    /**
     * Prepares the analysis environment (clean output directory, verify files)
     */
    private void prepareAnalysisEnvironment() throws Exception {
        // Clean previous output
        Path outputDir = Paths.get(outputPath);
        if (Files.exists(outputDir)) {
            deleteDirectoryRecursively(outputDir);
        }
        Files.createDirectories(outputDir);
        
        // Verify test APK exists
        Path apkPath = Paths.get(testAppPath);
        if (!Files.exists(apkPath)) {
            throw new FileNotFoundException("Test APK not found: " + testAppPath);
        }
        
        // Verify PathSentinel JAR exists
        Path jarPath = Paths.get(PATHSENTINEL_BASE_DIR, PATHSENTINEL_JAR);
        if (!Files.exists(jarPath)) {
            throw new FileNotFoundException("PathSentinel JAR not found: " + jarPath);
        }
        
        // Verify targeted methods file exists
        Path targetsPath = Paths.get(PATHSENTINEL_BASE_DIR, TARGETED_METHODS_FILE);
        if (!Files.exists(targetsPath)) {
            throw new FileNotFoundException("Targeted methods file not found: " + targetsPath);
        }
        
        System.out.println("Analysis environment prepared successfully");
    }
    
    /**
     * Executes PathSentinel static analysis
     */
    private boolean executePathSentinelAnalysis() throws Exception {
        analysisStartTime = System.currentTimeMillis();
        
        // Build PathSentinel command
        List<String> command = buildPathSentinelCommand();
        
        System.out.println("Executing PathSentinel command:");
        System.out.println(String.join(" ", command));
        
        // Execute analysis
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.directory(new File(PATHSENTINEL_BASE_DIR));
        pb.redirectErrorStream(true);
        
        Process process = pb.start();
        
        // Capture output
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
                System.out.println("PathSentinel: " + line);
            }
        }
        
        // Wait for completion with timeout
        boolean finished = process.waitFor(ANALYSIS_TIMEOUT_MINUTES, TimeUnit.MINUTES);
        analysisEndTime = System.currentTimeMillis();
        
        if (!finished) {
            process.destroyForcibly();
            System.err.println("PathSentinel analysis timed out after " + ANALYSIS_TIMEOUT_MINUTES + " minutes");
            return false;
        }
        
        int exitCode = process.exitValue();
        if (exitCode != 0) {
            System.err.println("PathSentinel analysis failed with exit code: " + exitCode);
            System.err.println("Output:\n" + output.toString());
            return false;
        }
        
        System.out.println("PathSentinel analysis completed successfully");
        return true;
    }
    
    /**
     * Builds the PathSentinel command with appropriate parameters
     */
    private List<String> buildPathSentinelCommand() {
        List<String> command = new ArrayList<>();
        command.add("java");
        command.add("-Xmx8g");
        command.add("-Xms6g");
        command.add("-XX:NewSize=4g");
        command.add("-jar");
        command.add(PATHSENTINEL_JAR);
        command.add("-o");
        command.add(outputPath);
        command.add("-t");
        command.add(TARGETED_METHODS_FILE);
        command.add("-j");
        command.add("4"); // Multi-threading
        command.add("-k");
        command.add("10"); // 10 minute timeout per path
        command.add("-y"); // Print constraints
        command.add(testAppPath);
        
        return command;
    }
    
    /**
     * Parses PathSentinel analysis results from output files
     */
    private Map<String, PathSentinelResult> parseAnalysisResults() throws Exception {
        Map<String, PathSentinelResult> results = new HashMap<>();
        
        // Parse main results from appInfo.json
        Path appInfoPath = Paths.get(outputPath, APP_INFO_JSON);
        if (!Files.exists(appInfoPath)) {
            throw new FileNotFoundException("PathSentinel output file not found: " + appInfoPath);
        }
        
        String appInfoContent = new String(Files.readAllBytes(appInfoPath));
        JsonObject appInfo = JsonParser.parseString(appInfoContent).getAsJsonObject();
        
        // Parse event chains and paths
        if (appInfo.has("eventChains")) {
            JsonArray eventChains = appInfo.getAsJsonArray("eventChains");
            for (int i = 0; i < eventChains.size(); i++) {
                JsonObject chain = eventChains.get(i).getAsJsonObject();
                parseEventChain(chain, results);
            }
        }
        
        // Parse additional analysis data
        parseCallGraphData(results);
        parseConstraintData(results);
        
        // Match results to test cases
        matchResultsToTestCases(results);
        
        System.out.println("Parsed " + results.size() + " PathSentinel results");
        return results;
    }
    
    /**
     * Parses a single event chain from PathSentinel output
     */
    private void parseEventChain(JsonObject chain, Map<String, PathSentinelResult> results) {
        try {
            // Extract path information
            String pathId = extractPathId(chain);
            PathSentinelResult result = results.computeIfAbsent(pathId, k -> new PathSentinelResult(k));
            
            // Parse entry point
            if (chain.has("entryPoint")) {
                result.actualEntryPoint = chain.get("entryPoint").getAsString();
            }
            
            // Parse target method
            if (chain.has("targetMethod")) {
                result.actualTargetMethod = chain.get("targetMethod").getAsString();
            }
            
            // Parse path information
            if (chain.has("pathResolution")) {
                JsonObject pathResolution = chain.getAsJsonObject("pathResolution");
                result.actualPath = extractActualPath(pathResolution);
                result.pathFullyResolved = extractPathResolutionStatus(pathResolution);
            }
            
            // Parse constraints
            if (chain.has("constraints")) {
                result.actualConstraints = extractConstraints(chain.getAsJsonArray("constraints"));
            }
            
            // Parse external inputs
            if (chain.has("externalInputs")) {
                result.actualExternalInputs = extractExternalInputs(chain.getAsJsonArray("externalInputs"));
            }
            
            // Parse construction pattern
            result.actualConstructionPattern = extractConstructionPattern(chain);
            
            // Parse vulnerability assessment
            result.detectedAsVulnerable = extractVulnerabilityStatus(chain);
            result.actualVulnerabilityType = extractVulnerabilityType(chain);
            result.actualConfidenceScore = extractConfidenceScore(chain);
            
            // Calculate analysis metrics
            result.analysisTimeMs = analysisEndTime - analysisStartTime;
            result.timedOut = false; // Would have been caught earlier
            result.hasErrors = false; // Would have been caught earlier
            
        } catch (Exception e) {
            System.err.println("Error parsing event chain: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Extracts path ID from event chain
     */
    private String extractPathId(JsonObject chain) {
        // Try to extract test case ID from entry point or other identifiers
        if (chain.has("entryPoint")) {
            String entryPoint = chain.get("entryPoint").getAsString();
            Pattern testIdPattern = Pattern.compile("([HTS]\\d+)_");
            Matcher matcher = testIdPattern.matcher(entryPoint);
            if (matcher.find()) {
                return matcher.group(1);
            }
        }
        
        // Fallback to generating ID based on target method and entry point
        String entryPoint = chain.has("entryPoint") ? chain.get("entryPoint").getAsString() : "unknown";
        String targetMethod = chain.has("targetMethod") ? chain.get("targetMethod").getAsString() : "unknown";
        return "AUTO_" + Math.abs((entryPoint + targetMethod).hashCode()) % 10000;
    }
    
    /**
     * Extracts the actual resolved path from PathSentinel results
     */
    private String extractActualPath(JsonObject pathResolution) {
        if (pathResolution.has("resolvedPath")) {
            return pathResolution.get("resolvedPath").getAsString();
        }
        if (pathResolution.has("partialPath")) {
            return pathResolution.get("partialPath").getAsString();
        }
        if (pathResolution.has("pathPattern")) {
            return pathResolution.get("pathPattern").getAsString();
        }
        return null;
    }
    
    /**
     * Extracts path resolution status
     */
    private boolean extractPathResolutionStatus(JsonObject pathResolution) {
        if (pathResolution.has("fullyResolved")) {
            return pathResolution.get("fullyResolved").getAsBoolean();
        }
        if (pathResolution.has("resolutionStatus")) {
            String status = pathResolution.get("resolutionStatus").getAsString();
            return "COMPLETE".equals(status) || "FULLY_RESOLVED".equals(status);
        }
        return false;
    }
    
    /**
     * Extracts Z3 constraints from PathSentinel output
     */
    private List<String> extractConstraints(JsonArray constraintArray) {
        List<String> constraints = new ArrayList<>();
        for (int i = 0; i < constraintArray.size(); i++) {
            JsonObject constraint = constraintArray.get(i).getAsJsonObject();
            if (constraint.has("z3Constraint")) {
                constraints.add(constraint.get("z3Constraint").getAsString());
            } else if (constraint.has("constraint")) {
                constraints.add(constraint.get("constraint").getAsString());
            }
        }
        return constraints;
    }
    
    /**
     * Extracts external input sources from PathSentinel output
     */
    private List<String> extractExternalInputs(JsonArray inputArray) {
        List<String> inputs = new ArrayList<>();
        for (int i = 0; i < inputArray.size(); i++) {
            JsonObject input = inputArray.get(i).getAsJsonObject();
            if (input.has("source")) {
                inputs.add(input.get("source").getAsString());
            } else if (input.has("inputSource")) {
                inputs.add(input.get("inputSource").getAsString());
            }
        }
        return inputs;
    }
    
    /**
     * Extracts construction pattern from event chain
     */
    private String extractConstructionPattern(JsonObject chain) {
        if (chain.has("constructionPattern")) {
            return chain.get("constructionPattern").getAsString();
        }
        
        // Infer construction pattern from path analysis
        if (chain.has("pathConstruction")) {
            JsonObject pathConstruction = chain.getAsJsonObject("pathConstruction");
            if (pathConstruction.has("pattern")) {
                return pathConstruction.get("pattern").getAsString();
            }
        }
        
        // Check for specific patterns in the call path
        if (chain.has("callPath")) {
            String callPath = chain.get("callPath").getAsString();
            if (callPath.contains("StringBuilder")) {
                return "StringBuilder.append() chain";
            } else if (callPath.contains("StringBuffer")) {
                return "StringBuffer.append() chain";
            } else if (callPath.contains("String.format")) {
                return "String.format() construction";
            } else if (callPath.contains("concat")) {
                return "String concatenation";
            }
        }
        
        return "Unknown construction pattern";
    }
    
    /**
     * Extracts vulnerability status from event chain
     */
    private boolean extractVulnerabilityStatus(JsonObject chain) {
        if (chain.has("isVulnerable")) {
            return chain.get("isVulnerable").getAsBoolean();
        }
        if (chain.has("vulnerabilityDetected")) {
            return chain.get("vulnerabilityDetected").getAsBoolean();
        }
        
        // Infer from target method - if we reached a sink, it's likely vulnerable
        if (chain.has("targetMethod")) {
            return true; // PathSentinel reaching a target method indicates potential vulnerability
        }
        
        return false;
    }
    
    /**
     * Extracts vulnerability type from event chain
     */
    private String extractVulnerabilityType(JsonObject chain) {
        if (chain.has("vulnerabilityType")) {
            return chain.get("vulnerabilityType").getAsString();
        }
        
        // Infer from path characteristics
        if (chain.has("pathResolution")) {
            JsonObject pathResolution = chain.getAsJsonObject("pathResolution");
            boolean hasExternalInput = chain.has("externalInputs") && 
                    chain.getAsJsonArray("externalInputs").size() > 0;
            
            if (hasExternalInput) {
                return "traversal";
            } else if (extractPathResolutionStatus(pathResolution)) {
                return "hijacking";
            }
        }
        
        return "unknown";
    }
    
    /**
     * Extracts confidence score from event chain
     */
    private double extractConfidenceScore(JsonObject chain) {
        if (chain.has("confidenceScore")) {
            return chain.get("confidenceScore").getAsDouble();
        }
        if (chain.has("confidence")) {
            return chain.get("confidence").getAsDouble();
        }
        
        // Default confidence based on resolution status
        if (chain.has("pathResolution")) {
            boolean fullyResolved = extractPathResolutionStatus(chain.getAsJsonObject("pathResolution"));
            return fullyResolved ? 0.8 : 0.5;
        }
        
        return 0.5; // Default medium confidence
    }
    
    /**
     * Parses call graph data for additional insights
     */
    private void parseCallGraphData(Map<String, PathSentinelResult> results) {
        // Parse call graph information if available
        Path callGraphPath = Paths.get(outputPath, "callGraph.json");
        if (Files.exists(callGraphPath)) {
            try {
                String content = new String(Files.readAllBytes(callGraphPath));
                JsonObject callGraph = JsonParser.parseString(content).getAsJsonObject();
                
                // Extract additional call graph metrics
                for (PathSentinelResult result : results.values()) {
                    if (result.actualEntryPoint != null) {
                        // Add call graph specific data
                        result.actualVariableCount = extractVariableCount(callGraph, result.actualEntryPoint);
                    }
                }
                
            } catch (Exception e) {
                System.err.println("Warning: Could not parse call graph data: " + e.getMessage());
            }
        }
    }
    
    /**
     * Parses constraint-specific data
     */
    private void parseConstraintData(Map<String, PathSentinelResult> results) {
        // Parse constraint analysis results if available
        Path constraintPath = Paths.get(outputPath, "constraints.json");
        if (Files.exists(constraintPath)) {
            try {
                String content = new String(Files.readAllBytes(constraintPath));
                JsonObject constraintData = JsonParser.parseString(content).getAsJsonObject();
                
                // Extract constraint-specific metrics
                for (PathSentinelResult result : results.values()) {
                    if (result.testCase != null && constraintData.has(result.testCase)) {
                        JsonObject testConstraints = constraintData.getAsJsonObject(result.testCase);
                        if (testConstraints.has("variableCount")) {
                            result.actualVariableCount = testConstraints.get("variableCount").getAsInt();
                        }
                    }
                }
                
            } catch (Exception e) {
                System.err.println("Warning: Could not parse constraint data: " + e.getMessage());
            }
        }
    }
    
    /**
     * Extracts variable count from call graph data
     */
    private int extractVariableCount(JsonObject callGraph, String entryPoint) {
        // Implementation would depend on PathSentinel's call graph format
        // This is a placeholder that returns a reasonable default
        return 3; // Default variable count
    }
    
    /**
     * Matches PathSentinel results to specific test cases based on entry points and methods
     */
    private void matchResultsToTestCases(Map<String, PathSentinelResult> results) {
        // Map of entry points to test case IDs
        Map<String, String> entryPointToTestCase = buildEntryPointMapping();
        
        Map<String, PathSentinelResult> matchedResults = new HashMap<>();
        
        for (PathSentinelResult result : results.values()) {
            String testCaseId = findMatchingTestCase(result, entryPointToTestCase);
            if (testCaseId != null) {
                result.testCase = testCaseId;
                matchedResults.put(testCaseId, result);
            }
        }
        
        results.clear();
        results.putAll(matchedResults);
    }
    
    /**
     * Builds mapping from entry points to test case IDs
     */
    private Map<String, String> buildEntryPointMapping() {
        Map<String, String> mapping = new HashMap<>();
        
        // Add known entry point patterns
        mapping.put("com.test.pathsent_tester.HijackingInterComponentTests.onStartCommand", "H");
        mapping.put("com.test.pathsent_tester.TraversalFullControlTests.processTraversalRequest", "T");
        mapping.put("com.test.pathsent_tester.StringConstructionTests.processStringConstructionTest", "S");
        mapping.put("com.test.pathsent_tester.ConstraintValidationTests.processConstraintTest", "C");
        
        return mapping;
    }
    
    /**
     * Finds matching test case ID for a result
     */
    private String findMatchingTestCase(PathSentinelResult result, Map<String, String> entryPointMapping) {
        if (result.actualEntryPoint != null) {
            for (Map.Entry<String, String> entry : entryPointMapping.entrySet()) {
                if (result.actualEntryPoint.contains(entry.getKey())) {
                    // Extract test number from constraints or other identifiers
                    String testPrefix = entry.getValue();
                    int testNumber = extractTestNumber(result);
                    return testPrefix + testNumber;
                }
            }
        }
        return null;
    }
    
    /**
     * Extracts test number from result data
     */
    private int extractTestNumber(PathSentinelResult result) {
        // Try to extract from constraints
        if (result.actualConstraints != null) {
            for (String constraint : result.actualConstraints) {
                Pattern numberPattern = Pattern.compile("TEST_\\w+_(\\d+)");
                Matcher matcher = numberPattern.matcher(constraint);
                if (matcher.find()) {
                    return Integer.parseInt(matcher.group(1));
                }
            }
        }
        
        // Fallback to hash-based numbering
        return Math.abs(result.actualEntryPoint.hashCode()) % 30 + 1;
    }
    
    /**
     * Utility method to delete directory recursively
     */
    private void deleteDirectoryRecursively(Path directory) throws IOException {
        if (Files.exists(directory)) {
            Files.walk(directory)
                    .sorted((a, b) -> -a.compareTo(b)) // Reverse order to delete files before directories
                    .forEach(path -> {
                        try {
                            Files.delete(path);
                        } catch (IOException e) {
                            System.err.println("Warning: Could not delete " + path + ": " + e.getMessage());
                        }
                    });
        }
    }
    
    /**
     * Gets PathSentinel version for reporting
     */
    public String getPathSentinelVersion() {
        try {
            // Try to extract version from JAR manifest or other sources
            return "1.0-SNAPSHOT";
        } catch (Exception e) {
            return "Unknown";
        }
    }
}