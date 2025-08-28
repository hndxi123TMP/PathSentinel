package validation;

import java.util.List;

/**
 * Represents the result of validating a single test case against its ground truth expectation.
 * Contains detailed comparison information and pass/fail status.
 */
public class ValidationResult {
    
    /** Test case identifier */
    public String testId;
    
    /** Overall validation status */
    public ValidationStatus status;
    
    /** Ground truth expectation */
    public GroundTruthExpectation expected;
    
    /** Actual PathSentinel result */
    public PathSentinelResult actual;
    
    /** Detailed validation findings */
    public List<ValidationFinding> findings;
    
    /** Overall score (0.0 - 1.0) */
    public double validationScore;
    
    /** Whether this is a critical failure */
    public boolean isCriticalFailure;
    
    /** Validation comments and notes */
    public String validationNotes;
    
    public enum ValidationStatus {
        PASS,           // All expectations met
        PARTIAL_PASS,   // Some expectations met
        FAIL,           // Major expectations not met
        ERROR,          // Analysis error or timeout
        CRITICAL_FAIL   // Critical functionality broken
    }
    
    public ValidationResult(String testId, GroundTruthExpectation expected, PathSentinelResult actual) {
        this.testId = testId;
        this.expected = expected;
        this.actual = actual;
        this.status = ValidationStatus.FAIL; // Default until validated
        this.validationScore = 0.0;
        this.isCriticalFailure = false;
        this.validationNotes = "";
    }
    
    /**
     * Checks if this validation passed (PASS or PARTIAL_PASS)
     */
    public boolean isPassed() {
        return status == ValidationStatus.PASS || status == ValidationStatus.PARTIAL_PASS;
    }
    
    /**
     * Checks if this validation failed critically
     */
    public boolean isCritical() {
        return status == ValidationStatus.CRITICAL_FAIL || isCriticalFailure;
    }
    
    /**
     * Gets a human-readable summary of the validation
     */
    public String getSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%s %s: %s", 
                status == ValidationStatus.PASS ? "✓" : 
                status == ValidationStatus.PARTIAL_PASS ? "~" : "✗",
                testId, status.name()));
        
        if (expected != null && actual != null) {
            sb.append(String.format(" - Expected: %s, Got: %s", 
                    expected.expectedPath, actual.actualPath));
        }
        
        if (validationScore > 0) {
            sb.append(String.format(" (Score: %.1f%%)", validationScore * 100));
        }
        
        return sb.toString();
    }
    
    @Override
    public String toString() {
        return getSummary();
    }
}

/**
 * Represents a specific validation finding (pass/fail for a particular aspect)
 */
class ValidationFinding {
    public String aspect;           // "path_resolution", "constraint_generation", etc.
    public boolean passed;
    public String expectedValue;
    public String actualValue;
    public String message;
    public double weight;           // Importance weight for scoring
    
    public ValidationFinding(String aspect, boolean passed, String expectedValue, 
            String actualValue, String message, double weight) {
        this.aspect = aspect;
        this.passed = passed;
        this.expectedValue = expectedValue;
        this.actualValue = actualValue;
        this.message = message;
        this.weight = weight;
    }
    
    @Override
    public String toString() {
        return String.format("%s %s: %s (Expected: %s, Actual: %s)",
                passed ? "✓" : "✗", aspect, message, expectedValue, actualValue);
    }
}