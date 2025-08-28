package validation;

import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Core validation utility that compares PathSentinel analysis results against expected ground truth.
 * Provides comprehensive validation across all test phases: hijacking, traversal, string construction, 
 * and constraint validation.
 */
public class GroundTruthValidator {
    
    private static final double PATH_RESOLUTION_WEIGHT = 0.3;
    private static final double CONSTRAINT_WEIGHT = 0.25;
    private static final double VULNERABILITY_TYPE_WEIGHT = 0.2;
    private static final double EXTERNAL_INPUT_WEIGHT = 0.15;
    private static final double CONSTRUCTION_PATTERN_WEIGHT = 0.1;
    
    /**
     * Validates Phase 1 hijacking test results against expected outcomes
     */
    public static List<ValidationResult> validateHijackingResults(
            Map<String, GroundTruthExpectation> expectations,
            Map<String, PathSentinelResult> actualResults) {
        
        List<ValidationResult> results = new ArrayList<>();
        
        for (String testId : expectations.keySet()) {
            if (testId.startsWith("H")) { // Hijacking tests
                GroundTruthExpectation expected = expectations.get(testId);
                PathSentinelResult actual = actualResults.get(testId);
                
                ValidationResult result = validateSingleTest(expected, actual);
                
                // Additional hijacking-specific validation
                if (actual != null && expected != null) {
                    validateHijackingSpecific(result, expected, actual);
                }
                
                results.add(result);
            }
        }
        
        return results;
    }
    
    /**
     * Validates Phase 2 traversal test results
     */
    public static List<ValidationResult> validateTraversalResults(
            Map<String, GroundTruthExpectation> expectations,
            Map<String, PathSentinelResult> actualResults) {
        
        List<ValidationResult> results = new ArrayList<>();
        
        for (String testId : expectations.keySet()) {
            if (testId.startsWith("T")) { // Traversal tests
                GroundTruthExpectation expected = expectations.get(testId);
                PathSentinelResult actual = actualResults.get(testId);
                
                ValidationResult result = validateSingleTest(expected, actual);
                
                // Additional traversal-specific validation
                if (actual != null && expected != null) {
                    validateTraversalSpecific(result, expected, actual);
                }
                
                results.add(result);
            }
        }
        
        return results;
    }
    
    /**
     * Validates Phase 3 string construction test results
     */
    public static List<ValidationResult> validateStringConstructionResults(
            Map<String, GroundTruthExpectation> expectations,
            Map<String, PathSentinelResult> actualResults) {
        
        List<ValidationResult> results = new ArrayList<>();
        
        for (String testId : expectations.keySet()) {
            if (testId.startsWith("S")) { // String construction tests
                GroundTruthExpectation expected = expectations.get(testId);
                PathSentinelResult actual = actualResults.get(testId);
                
                ValidationResult result = validateSingleTest(expected, actual);
                
                // Additional string construction-specific validation
                if (actual != null && expected != null) {
                    validateStringConstructionSpecific(result, expected, actual);
                }
                
                results.add(result);
            }
        }
        
        return results;
    }
    
    /**
     * Validates Phase 4 constraint collection accuracy
     */
    public static List<ValidationResult> validateConstraintResults(
            Map<String, GroundTruthExpectation> expectations,
            Map<String, PathSentinelResult> actualResults) {
        
        List<ValidationResult> results = new ArrayList<>();
        
        for (String testId : expectations.keySet()) {
            if (testId.startsWith("C")) { // Constraint validation tests
                GroundTruthExpectation expected = expectations.get(testId);
                PathSentinelResult actual = actualResults.get(testId);
                
                ValidationResult result = validateSingleTest(expected, actual);
                
                // Additional constraint-specific validation
                if (actual != null && expected != null) {
                    validateConstraintSpecific(result, expected, actual);
                }
                
                results.add(result);
            }
        }
        
        return results;
    }
    
    /**
     * Core validation logic for a single test case
     */
    private static ValidationResult validateSingleTest(GroundTruthExpectation expected, PathSentinelResult actual) {
        if (expected == null) {
            throw new IllegalArgumentException("Expected result cannot be null");
        }
        
        ValidationResult result = new ValidationResult(expected.testId, expected, actual);
        result.findings = new ArrayList<>();
        
        // Handle analysis errors or timeouts
        if (actual == null || !actual.isSuccessful()) {
            result.status = ValidationResult.ValidationStatus.ERROR;
            result.validationScore = 0.0;
            result.validationNotes = actual != null ? actual.getSummary() : "No analysis result";
            return result;
        }
        
        // Validate path resolution
        ValidationFinding pathFinding = validatePathResolution(expected, actual);
        result.findings.add(pathFinding);
        
        // Validate vulnerability type detection
        ValidationFinding vulnTypeFinding = validateVulnerabilityType(expected, actual);
        result.findings.add(vulnTypeFinding);
        
        // Validate constraint generation
        ValidationFinding constraintFinding = validateConstraints(expected, actual);
        result.findings.add(constraintFinding);
        
        // Validate external input detection
        ValidationFinding inputFinding = validateExternalInputs(expected, actual);
        result.findings.add(inputFinding);
        
        // Validate construction pattern detection
        ValidationFinding constructionFinding = validateConstructionPattern(expected, actual);
        result.findings.add(constructionFinding);
        
        // Calculate overall score and status
        calculateValidationScore(result);
        
        return result;
    }
    
    /**
     * Validates path resolution accuracy
     */
    private static ValidationFinding validatePathResolution(GroundTruthExpectation expected, PathSentinelResult actual) {
        boolean passed = false;
        String message = "";
        
        if (expected.shouldResolveCompletely && actual.pathFullyResolved) {
            // Check exact path match or pattern match
            if (expected.expectedPath.equals(actual.actualPath)) {
                passed = true;
                message = "Exact path match";
            } else if (isPathPatternMatch(expected.expectedPath, actual.actualPath)) {
                passed = true;
                message = "Path pattern match";
            } else {
                message = "Path mismatch";
            }
        } else if (!expected.shouldResolveCompletely && !actual.pathFullyResolved) {
            // For user-controlled paths, check if properly identified as unresolved
            passed = true;
            message = "Correctly identified as unresolvable";
        } else {
            message = expected.shouldResolveCompletely ? "Should resolve but didn't" : "Shouldn't resolve but did";
        }
        
        return new ValidationFinding("path_resolution", passed, expected.expectedPath, 
                actual.actualPath, message, PATH_RESOLUTION_WEIGHT);
    }
    
    /**
     * Validates vulnerability type detection
     */
    private static ValidationFinding validateVulnerabilityType(GroundTruthExpectation expected, PathSentinelResult actual) {
        boolean passed = expected.vulnerabilityType.equals(actual.actualVulnerabilityType);
        String message = passed ? "Vulnerability type correctly identified" : "Vulnerability type mismatch";
        
        return new ValidationFinding("vulnerability_type", passed, expected.vulnerabilityType,
                actual.actualVulnerabilityType, message, VULNERABILITY_TYPE_WEIGHT);
    }
    
    /**
     * Validates Z3 constraint generation
     */
    private static ValidationFinding validateConstraints(GroundTruthExpectation expected, PathSentinelResult actual) {
        boolean passed = false;
        String message = "";
        
        if (expected.expectedConstraints == null || expected.expectedConstraints.isEmpty()) {
            passed = actual.actualConstraints == null || actual.actualConstraints.isEmpty();
            message = passed ? "No constraints expected or generated" : "Unexpected constraints generated";
        } else {
            // Check if expected constraints are present in actual constraints
            int matchedConstraints = 0;
            for (String expectedConstraint : expected.expectedConstraints) {
                if (actual.actualConstraints.stream().anyMatch(ac -> constraintMatches(expectedConstraint, ac))) {
                    matchedConstraints++;
                }
            }
            
            double matchRatio = (double) matchedConstraints / expected.expectedConstraints.size();
            passed = matchRatio >= 0.8; // 80% of expected constraints should be present
            message = String.format("Constraint match: %d/%d (%.1f%%)", 
                    matchedConstraints, expected.expectedConstraints.size(), matchRatio * 100);
        }
        
        return new ValidationFinding("constraint_generation", passed, 
                expected.expectedConstraints != null ? String.join("; ", expected.expectedConstraints) : "none",
                actual.actualConstraints != null ? String.join("; ", actual.actualConstraints) : "none",
                message, CONSTRAINT_WEIGHT);
    }
    
    /**
     * Validates external input detection
     */
    private static ValidationFinding validateExternalInputs(GroundTruthExpectation expected, PathSentinelResult actual) {
        boolean passed = false;
        String message = "";
        
        if (expected.expectedExternalInputs == null || expected.expectedExternalInputs.isEmpty()) {
            passed = actual.actualExternalInputs == null || actual.actualExternalInputs.isEmpty();
            message = passed ? "No external inputs expected or found" : "Unexpected external inputs found";
        } else {
            // Check overlap between expected and actual external inputs
            Set<String> expectedSet = new HashSet<>(expected.expectedExternalInputs);
            Set<String> actualSet = actual.actualExternalInputs != null ? 
                    new HashSet<>(actual.actualExternalInputs) : new HashSet<>();
            
            Set<String> intersection = new HashSet<>(expectedSet);
            intersection.retainAll(actualSet);
            
            double overlapRatio = expectedSet.isEmpty() ? 1.0 : (double) intersection.size() / expectedSet.size();
            passed = overlapRatio >= 0.7; // 70% overlap required
            message = String.format("External input overlap: %d/%d (%.1f%%)", 
                    intersection.size(), expectedSet.size(), overlapRatio * 100);
        }
        
        return new ValidationFinding("external_inputs", passed,
                expected.expectedExternalInputs != null ? String.join("; ", expected.expectedExternalInputs) : "none",
                actual.actualExternalInputs != null ? String.join("; ", actual.actualExternalInputs) : "none",
                message, EXTERNAL_INPUT_WEIGHT);
    }
    
    /**
     * Validates construction pattern detection
     */
    private static ValidationFinding validateConstructionPattern(GroundTruthExpectation expected, PathSentinelResult actual) {
        boolean passed = false;
        String message = "";
        
        if (expected.expectedConstructionPattern == null || expected.expectedConstructionPattern.isEmpty()) {
            passed = actual.actualConstructionPattern == null || actual.actualConstructionPattern.isEmpty();
            message = passed ? "No construction pattern expected or found" : "Unexpected construction pattern found";
        } else {
            passed = expected.expectedConstructionPattern.equals(actual.actualConstructionPattern) ||
                    (actual.actualConstructionPattern != null && 
                     actual.actualConstructionPattern.contains(expected.expectedConstructionPattern));
            message = passed ? "Construction pattern correctly identified" : "Construction pattern mismatch";
        }
        
        return new ValidationFinding("construction_pattern", passed, 
                expected.expectedConstructionPattern != null ? expected.expectedConstructionPattern : "none",
                actual.actualConstructionPattern != null ? actual.actualConstructionPattern : "none",
                message, CONSTRUCTION_PATTERN_WEIGHT);
    }
    
    /**
     * Additional validation specific to hijacking tests
     */
    private static void validateHijackingSpecific(ValidationResult result, GroundTruthExpectation expected, PathSentinelResult actual) {
        // Check if static paths are properly resolved
        if ("HARD_CODED".equals(expected.pathType)) {
            if (!actual.pathFullyResolved) {
                result.isCriticalFailure = true;
                result.validationNotes += "CRITICAL: Hard-coded path not fully resolved. ";
            }
        }
        
        // Check for proper hijacking detection
        if ("hijacking".equals(expected.vulnerabilityType) && !actual.detectedAsVulnerable) {
            result.validationNotes += "WARNING: Hijacking vulnerability not detected. ";
        }
    }
    
    /**
     * Additional validation specific to traversal tests
     */
    private static void validateTraversalSpecific(ValidationResult result, GroundTruthExpectation expected, PathSentinelResult actual) {
        // Check if user-controlled paths are properly identified
        if ("FULLY_CONTROLLED".equals(expected.pathType)) {
            if (actual.pathFullyResolved) {
                result.validationNotes += "WARNING: User-controlled path was unexpectedly resolved. ";
            }
            if (actual.actualExternalInputs == null || actual.actualExternalInputs.isEmpty()) {
                result.isCriticalFailure = true;
                result.validationNotes += "CRITICAL: External inputs not detected for traversal. ";
            }
        }
    }
    
    /**
     * Additional validation specific to string construction tests
     */
    private static void validateStringConstructionSpecific(ValidationResult result, GroundTruthExpectation expected, PathSentinelResult actual) {
        // Check if StringBuilder patterns are properly handled
        if (expected.expectedConstructionPattern != null && 
            expected.expectedConstructionPattern.contains("StringBuilder")) {
            if (actual.actualConstructionPattern == null || 
                !actual.actualConstructionPattern.contains("StringBuilder")) {
                result.isCriticalFailure = true;
                result.validationNotes += "CRITICAL: StringBuilder pattern not detected. ";
            }
        }
        
        // Check if complex construction is properly resolved
        if (expected.expectedConstructionPattern != null && 
            expected.expectedConstructionPattern.contains("Complex")) {
            if (!actual.pathFullyResolved) {
                result.validationNotes += "WARNING: Complex construction not fully resolved. ";
            }
        }
    }
    
    /**
     * Additional validation specific to constraint tests
     */
    private static void validateConstraintSpecific(ValidationResult result, GroundTruthExpectation expected, PathSentinelResult actual) {
        // Check constraint count
        int expectedCount = expected.expectedVariableCount;
        int actualCount = actual.actualVariableCount;
        
        if (Math.abs(expectedCount - actualCount) > expectedCount * 0.3) { // 30% tolerance
            result.validationNotes += String.format("WARNING: Variable count mismatch (expected: %d, actual: %d). ", 
                    expectedCount, actualCount);
        }
        
        // Check for nested constraints if expected
        if (expected.expectedConstraints != null) {
            long nestedExpected = expected.expectedConstraints.stream()
                    .mapToLong(c -> c.chars().filter(ch -> ch == '(').count()).sum();
            long nestedActual = actual.actualConstraints != null ? 
                    actual.actualConstraints.stream()
                            .mapToLong(c -> c.chars().filter(ch -> ch == '(').count()).sum() : 0;
            
            if (nestedExpected > 0 && nestedActual == 0) {
                result.isCriticalFailure = true;
                result.validationNotes += "CRITICAL: Nested constraints not generated. ";
            }
        }
    }
    
    /**
     * Calculates overall validation score and determines pass/fail status
     */
    private static void calculateValidationScore(ValidationResult result) {
        double totalWeight = 0.0;
        double weightedScore = 0.0;
        
        for (ValidationFinding finding : result.findings) {
            totalWeight += finding.weight;
            if (finding.passed) {
                weightedScore += finding.weight;
            }
        }
        
        result.validationScore = totalWeight > 0 ? weightedScore / totalWeight : 0.0;
        
        // Determine status based on score and critical failures
        if (result.isCriticalFailure) {
            result.status = ValidationResult.ValidationStatus.CRITICAL_FAIL;
        } else if (result.validationScore >= 0.9) {
            result.status = ValidationResult.ValidationStatus.PASS;
        } else if (result.validationScore >= 0.6) {
            result.status = ValidationResult.ValidationStatus.PARTIAL_PASS;
        } else {
            result.status = ValidationResult.ValidationStatus.FAIL;
        }
    }
    
    /**
     * Checks if a path matches a pattern (supports wildcards and placeholders)
     */
    private static boolean isPathPatternMatch(String pattern, String actualPath) {
        if (pattern == null || actualPath == null) return false;
        
        // Handle placeholder patterns like "/data/app/files/[id].log"
        String regexPattern = pattern
                .replaceAll("\\[\\w+\\]", "\\\\w+")  // [id] -> \w+
                .replaceAll("\\*", ".*")             // * -> .*
                .replaceAll("\\?", ".");             // ? -> .
        
        return Pattern.matches(regexPattern, actualPath);
    }
    
    /**
     * Checks if two constraints are semantically equivalent
     */
    private static boolean constraintMatches(String expected, String actual) {
        if (expected == null || actual == null) return false;
        
        // Simple string containment for now - could be enhanced with Z3 semantic comparison
        return actual.contains(expected) || expected.contains(actual) ||
               normalizeConstraint(expected).equals(normalizeConstraint(actual));
    }
    
    /**
     * Normalizes constraint strings for comparison
     */
    private static String normalizeConstraint(String constraint) {
        return constraint.replaceAll("\\s+", " ")
                .replaceAll("\\(\\s+", "(")
                .replaceAll("\\s+\\)", ")")
                .trim().toLowerCase();
    }
    
    /**
     * Generates a comprehensive validation report for all test phases
     */
    public static ValidationReport generateComprehensiveReport(
            Map<String, GroundTruthExpectation> expectations,
            Map<String, PathSentinelResult> actualResults) {
        
        ValidationReport report = new ValidationReport();
        
        // Validate each phase
        report.hijackingResults = validateHijackingResults(expectations, actualResults);
        report.traversalResults = validateTraversalResults(expectations, actualResults);
        report.stringConstructionResults = validateStringConstructionResults(expectations, actualResults);
        report.constraintResults = validateConstraintResults(expectations, actualResults);
        
        // Calculate overall statistics
        report.calculateOverallStatistics();
        
        return report;
    }
}