package pathsent.target.constraint;

import soot.SootMethod;
import soot.Value;
import soot.jimple.InvokeExpr;

import java.util.*;

/**
 * TaintTracker - Framework for comprehensive external input tracking
 * 
 * This class implements a taint analysis system that:
 * 1. Identifies external input sources (Intent, ContentValues, URI, Bundle, etc.)
 * 2. Propagates taint through string operations and method calls
 * 3. Classifies paths based on taint information
 */
public class TaintTracker {
    
    /**
     * Taint information for a variable or expression
     */
    public static class TaintInfo {
        public enum TaintType {
            CLEAN,              // No taint (hard-coded values)
            PARTIALLY_TAINTED,  // Mix of tainted and clean data
            FULLY_TAINTED       // Completely from external sources
        }
        
        private final TaintType taintType;
        private final Set<ExternalInputSource> taintSources;
        private final String description;
        
        public TaintInfo(TaintType type, Set<ExternalInputSource> sources, String description) {
            this.taintType = type;
            this.taintSources = sources != null ? new HashSet<>(sources) : new HashSet<>();
            this.description = description;
        }
        
        public TaintType getTaintType() { return taintType; }
        public Set<ExternalInputSource> getTaintSources() { return new HashSet<>(taintSources); }
        public String getDescription() { return description; }
        
        /**
         * Create clean (untainted) info
         */
        public static TaintInfo clean(String description) {
            return new TaintInfo(TaintType.CLEAN, Collections.emptySet(), description);
        }
        
        /**
         * Create fully tainted info
         */
        public static TaintInfo fullyTainted(ExternalInputSource source, String description) {
            return new TaintInfo(TaintType.FULLY_TAINTED, Collections.singleton(source), description);
        }
        
        /**
         * Combine two taint infos (for operations like string concatenation)
         */
        public static TaintInfo combine(TaintInfo left, TaintInfo right, String description) {
            Set<ExternalInputSource> combinedSources = new HashSet<>();
            combinedSources.addAll(left.getTaintSources());
            combinedSources.addAll(right.getTaintSources());
            
            TaintType combinedType;
            if (left.taintType == TaintType.CLEAN && right.taintType == TaintType.CLEAN) {
                combinedType = TaintType.CLEAN;
            } else if (left.taintType == TaintType.FULLY_TAINTED && right.taintType == TaintType.FULLY_TAINTED) {
                combinedType = TaintType.FULLY_TAINTED;
            } else {
                combinedType = TaintType.PARTIALLY_TAINTED;
            }
            
            return new TaintInfo(combinedType, combinedSources, description);
        }
    }
    
    /**
     * External input source information
     */
    public static class ExternalInputSource {
        private final String sourceType;     // "intent", "uri", "bundle", "content_values"
        private final String sourceMethod;   // "getStringExtra", "getLastPathSegment", etc.
        private final String sourceParameter; // Parameter value (e.g., "filename")
        private final String fullDescription; // Full method call description
        private final SootMethod entryPoint; // Entry point method where this source originates
        
        public ExternalInputSource(String sourceType, String sourceMethod, 
                                 String sourceParameter, String fullDescription, SootMethod entryPoint) {
            this.sourceType = sourceType;
            this.sourceMethod = sourceMethod;
            this.sourceParameter = sourceParameter;
            this.fullDescription = fullDescription;
            this.entryPoint = entryPoint;
        }
        
        public String getSourceType() { return sourceType; }
        public String getSourceMethod() { return sourceMethod; }
        public String getSourceParameter() { return sourceParameter; }
        public String getFullDescription() { return fullDescription; }
        public SootMethod getEntryPoint() { return entryPoint; }
        
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            ExternalInputSource that = (ExternalInputSource) o;
            return Objects.equals(sourceType, that.sourceType) &&
                   Objects.equals(sourceMethod, that.sourceMethod) &&
                   Objects.equals(sourceParameter, that.sourceParameter) &&
                   Objects.equals(fullDescription, that.fullDescription);
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(sourceType, sourceMethod, sourceParameter, fullDescription);
        }
        
        @Override
        public String toString() {
            if (fullDescription != null) {
                return fullDescription;
            }
            StringBuilder sb = new StringBuilder();
            sb.append(sourceType).append(".").append(sourceMethod);
            if (sourceParameter != null) {
                sb.append("(\"").append(sourceParameter).append("\")");
            } else {
                sb.append("(?)");
            }
            return sb.toString();
        }
    }
    
    // Cache for taint information to avoid recomputation
    private final Map<Variable, TaintInfo> variableTaintCache = new HashMap<>();
    private final Map<String, Boolean> methodTaintCache = new HashMap<>();
    
    /**
     * Analyze taint for a variable
     */
    public TaintInfo analyzeTaint(Variable variable) {
        if (variableTaintCache.containsKey(variable)) {
            return variableTaintCache.get(variable);
        }
        
        TaintInfo taint = computeTaint(variable);
        variableTaintCache.put(variable, taint);
        return taint;
    }
    
    /**
     * Compute taint information for a variable
     */
    private TaintInfo computeTaint(Variable variable) {
        if (variable instanceof StringVariable) {
            // Hard-coded string literals are always clean
            return TaintInfo.clean("hard-coded string: \"" + ((StringVariable)variable).getValue() + "\"");
        } else if (variable instanceof InputVariable) {
            // Input variables are always fully tainted
            ExternalInputSource source = new ExternalInputSource(
                "input", "parameter", null, variable.toString(), null);
            return TaintInfo.fullyTainted(source, "input parameter: " + variable.toString());
        } else if (variable instanceof MethodCallVariable) {
            return analyzeMethodCallTaint((MethodCallVariable) variable);
        } else if (variable instanceof FieldAccessVariable) {
            // Field access could be tainted depending on the field
            // For now, assume potentially tainted (conservative approach)
            ExternalInputSource source = new ExternalInputSource(
                "field", "access", null, variable.toString(), null);
            return TaintInfo.fullyTainted(source, "field access: " + variable.toString());
        } else {
            // Other variable types - assume potentially tainted for safety
            return TaintInfo.fullyTainted(
                new ExternalInputSource("unknown", "variable", null, variable.toString(), null),
                "unknown variable: " + variable.toString());
        }
    }
    
    /**
     * Analyze taint for method call variables
     */
    private TaintInfo analyzeMethodCallTaint(MethodCallVariable mcv) {
        String methodSig = mcv.getMethod().getSignature();
        
        // Check if this is a known external input method
        if (isExternalInputMethod(methodSig)) {
            ExternalInputSource source = createExternalInputSource(mcv);
            return TaintInfo.fullyTainted(source, "external input: " + source.toString());
        }
        
        // Check if this is a string manipulation method (toString, substring, etc.)
        if (isStringManipulationMethod(methodSig)) {
            // For string manipulation, taint depends on the receiver
            Variable receiver = mcv.getReceiverVariable();
            if (receiver != null) {
                TaintInfo receiverTaint = analyzeTaint(receiver);
                return new TaintInfo(receiverTaint.getTaintType(), receiverTaint.getTaintSources(),
                                   "string manipulation of: " + receiverTaint.getDescription());
            }
        }
        
        // For other method calls, assume potentially tainted (conservative)
        ExternalInputSource source = new ExternalInputSource(
            "method", mcv.getMethod().getName(), null, mcv.getMethodCallDescription(), null);
        return TaintInfo.fullyTainted(source, "method call: " + mcv.getMethodCallDescription());
    }
    
    /**
     * Check if a method signature represents an external input source
     */
    private boolean isExternalInputMethod(String methodSig) {
        // Intent methods
        if (methodSig.contains("android.content.Intent") && (
            methodSig.contains("getStringExtra") ||
            methodSig.contains("getIntExtra") ||
            methodSig.contains("getBooleanExtra") ||
            methodSig.contains("getExtras"))) {
            return true;
        }
        
        // URI methods
        if (methodSig.contains("android.net.Uri") && (
            methodSig.contains("getQueryParameter") ||
            methodSig.contains("getLastPathSegment") ||
            methodSig.contains("getPath"))) {
            return true;
        }
        
        // Bundle methods
        if (methodSig.contains("android.os.Bundle") && (
            methodSig.contains("getString") ||
            methodSig.contains("get("))) {
            return true;
        }
        
        // ContentValues methods
        if (methodSig.contains("android.content.ContentValues") && (
            methodSig.contains("getAsString") ||
            methodSig.contains("get("))) {
            return true;
        }
        
        // SharedPreferences methods
        if (methodSig.contains("android.content.SharedPreferences") && (
            methodSig.contains("getString"))) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if a method is a string manipulation method that preserves taint
     */
    private boolean isStringManipulationMethod(String methodSig) {
        return methodSig.endsWith("java.lang.String toString()>") ||
               methodSig.contains("java.lang.String substring(") ||
               methodSig.contains("java.lang.String trim()>") ||
               methodSig.contains("java.lang.String toLowerCase()>") ||
               methodSig.contains("java.lang.String toUpperCase()>");
    }
    
    /**
     * Create external input source from method call variable
     */
    private ExternalInputSource createExternalInputSource(MethodCallVariable mcv) {
        String methodSig = mcv.getMethod().getSignature();
        String sourceType = "unknown";
        
        if (methodSig.contains("android.content.Intent")) {
            sourceType = "intent";
        } else if (methodSig.contains("android.net.Uri")) {
            sourceType = "uri";
        } else if (methodSig.contains("android.os.Bundle")) {
            sourceType = "bundle";
        } else if (methodSig.contains("android.content.ContentValues")) {
            sourceType = "content_values";
        } else if (methodSig.contains("android.content.SharedPreferences")) {
            sourceType = "shared_preferences";
        }
        
        String sourceMethod = mcv.getMethod().getName();
        String sourceParameter = mcv.getStringParameter(0); // First string parameter
        String fullDescription = mcv.getMethodCallDescription();
        
        return new ExternalInputSource(sourceType, sourceMethod, sourceParameter, 
                                     fullDescription, null);
    }
    
    /**
     * Classify path type based on taint analysis
     */
    public StringParameterConstraint.PathType classifyPathType(TaintInfo taintInfo) {
        switch (taintInfo.getTaintType()) {
            case CLEAN:
                return StringParameterConstraint.PathType.HARD_CODED;
            case PARTIALLY_TAINTED:
                return StringParameterConstraint.PathType.PARTIALLY_CONTROLLED;
            case FULLY_TAINTED:
                return StringParameterConstraint.PathType.FULLY_CONTROLLED;
            default:
                return StringParameterConstraint.PathType.FULLY_CONTROLLED; // Conservative default
        }
    }
    
    /**
     * Clear caches (call between analyses)
     */
    public void clearCaches() {
        variableTaintCache.clear();
        methodTaintCache.clear();
    }
}