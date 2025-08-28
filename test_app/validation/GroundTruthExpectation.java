package validation;

import java.util.List;

/**
 * Represents the expected ground truth for a single PathSentinel test case.
 * Each test case has specific expected outcomes for path resolution, constraint generation,
 * and vulnerability detection that PathSentinel should achieve.
 */
public class GroundTruthExpectation {
    
    /** Test identifier (e.g., "H1", "T2", "S3", "C4") */
    public String testId;
    
    /** Test method name (e.g., "testSimpleStaticPath") */
    public String testMethod;
    
    /** Vulnerability type: "hijacking", "traversal", "construction", "constraint" */
    public String vulnerabilityType;
    
    /** Path control type: "HARD_CODED", "PARTIALLY_CONTROLLED", "FULLY_CONTROLLED" */
    public String pathType;
    
    /** Expected resolved file path (or pattern like "<user_controlled>") */
    public String expectedPath;
    
    /** Expected Z3 constraint patterns that should be generated */
    public List<String> expectedConstraints;
    
    /** Expected number of symbolic variables PathSentinel should track */
    public int expectedVariableCount;
    
    /** Expected external input sources (Intent extras, Uri paths, etc.) */
    public List<String> expectedExternalInputs;
    
    /** Expected path construction pattern (StringBuilder, concatenation, etc.) */
    public String expectedConstructionPattern;
    
    /** Whether PathSentinel should fully resolve the complete path */
    public boolean shouldResolveCompletely;
    
    /** Expected entry point that should trigger this test */
    public String expectedEntryPoint;
    
    /** Expected target method that should be reached */
    public String expectedTargetMethod;
    
    /** Expected obfuscation techniques present in this test */
    public List<String> expectedObfuscationTechniques;
    
    /** Whether this test represents a true vulnerability */
    public boolean isVulnerable;
    
    /** Expected confidence score (0.0 - 1.0) PathSentinel should assign */
    public double expectedConfidenceScore;
    
    public GroundTruthExpectation() {}
    
    public GroundTruthExpectation(String testId, String testMethod, String vulnerabilityType,
            String pathType, String expectedPath, List<String> expectedConstraints,
            int expectedVariableCount, List<String> expectedExternalInputs,
            String expectedConstructionPattern, boolean shouldResolveCompletely) {
        this.testId = testId;
        this.testMethod = testMethod;
        this.vulnerabilityType = vulnerabilityType;
        this.pathType = pathType;
        this.expectedPath = expectedPath;
        this.expectedConstraints = expectedConstraints;
        this.expectedVariableCount = expectedVariableCount;
        this.expectedExternalInputs = expectedExternalInputs;
        this.expectedConstructionPattern = expectedConstructionPattern;
        this.shouldResolveCompletely = shouldResolveCompletely;
        this.isVulnerable = true; // Default to vulnerable
        this.expectedConfidenceScore = 0.8; // Default confidence
    }
    
    @Override
    public String toString() {
        return String.format("GroundTruthExpectation{testId='%s', testMethod='%s', " +
                "vulnerabilityType='%s', pathType='%s', expectedPath='%s'}",
                testId, testMethod, vulnerabilityType, pathType, expectedPath);
    }
}