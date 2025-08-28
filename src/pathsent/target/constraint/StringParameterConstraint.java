package pathsent.target.constraint;

import soot.SootMethod;
import soot.Value;
import java.util.List;
import java.util.ArrayList;

/**
 * Represents constraints on a String parameter of a targeted method.
 * Tracks how the string parameter is constructed and what constraints apply to it.
 */
public class StringParameterConstraint {
    
    /**
     * Path vulnerability types
     */
    public enum PathType {
        HARD_CODED,           // Type 1: Hijacking vulnerability (predictable path)
        PARTIALLY_CONTROLLED, // Type 2: Traversal with base path constraint
        FULLY_CONTROLLED      // Type 3: Traversal with full control
    }
    
    /**
     * Represents an external input source
     */
    public static class ExternalInputSource {
        private String variableName;      // e.g., "filename"
        private String sourceType;        // e.g., "intent", "bundle", "uri"
        private String sourceMethod;      // e.g., "getStringExtra", "getQueryParameter"
        private String sourceParameter;   // e.g., "filename" (the key/parameter name)
        private String fullSourceString;  // e.g., "intent.getStringExtra(\"filename\")"
        private SootMethod entryPoint;    // Where the input enters the system
        
        public ExternalInputSource() {}
        
        // Getters and setters
        public String getVariableName() { return variableName; }
        public void setVariableName(String name) { this.variableName = name; }
        
        public String getSourceType() { return sourceType; }
        public void setSourceType(String type) { this.sourceType = type; }
        
        public String getSourceMethod() { return sourceMethod; }
        public void setSourceMethod(String method) { this.sourceMethod = method; }
        
        public String getSourceParameter() { return sourceParameter; }
        public void setSourceParameter(String param) { this.sourceParameter = param; }
        
        public String getFullSourceString() { return fullSourceString; }
        public void setFullSourceString(String source) { this.fullSourceString = source; }
        
        public SootMethod getEntryPoint() { return entryPoint; }
        public void setEntryPoint(SootMethod entry) { this.entryPoint = entry; }
        
        @Override
        public String toString() {
            return fullSourceString != null ? fullSourceString : 
                   sourceType + "." + sourceMethod + "(\"" + sourceParameter + "\")";
        }
    }
    
    private final SootMethod targetMethod;
    private final int parameterIndex;
    private final String parameterName;
    private final Value parameterValue;
    private final ExpressionSet parameterExpressions;
    private final List<String> constructionComponents;
    private final List<ExternalInputSource> externalInputSources;
    private Predicate constraints;
    
    // Path type classification
    private PathType pathType;
    private String hardCodedValue;      // For HARD_CODED paths
    private String hardCodedPrefix;     // For PARTIALLY_CONTROLLED paths
    private String constructionPattern;  // e.g., "BASE_PATH + INPUT"

    public StringParameterConstraint(SootMethod targetMethod, int parameterIndex, 
                                   String parameterName, Value parameterValue,
                                   ExpressionSet parameterExpressions) {
        this.targetMethod = targetMethod;
        this.parameterIndex = parameterIndex;
        this.parameterName = parameterName;
        this.parameterValue = parameterValue;
        this.parameterExpressions = parameterExpressions;
        this.constructionComponents = new ArrayList<>();
        this.externalInputSources = new ArrayList<>();
        this.constraints = null;
        this.pathType = null;
        this.hardCodedValue = null;
        this.hardCodedPrefix = null;
        this.constructionPattern = null;
    }

    public SootMethod getTargetMethod() {
        return targetMethod;
    }

    public int getParameterIndex() {
        return parameterIndex;
    }

    public String getParameterName() {
        return parameterName;
    }

    public Value getParameterValue() {
        return parameterValue;
    }

    public ExpressionSet getParameterExpressions() {
        return parameterExpressions;
    }

    public List<String> getConstructionComponents() {
        return constructionComponents;
    }

    public void addConstructionComponent(String component) {
        constructionComponents.add(component);
    }

    public Predicate getConstraints() {
        return constraints;
    }

    public void setConstraints(Predicate constraints) {
        this.constraints = constraints;
    }

    public void addConstraint(Predicate constraint) {
        if (this.constraints == null) {
            this.constraints = constraint;
        } else {
            this.constraints = Predicate.combine(Predicate.Operator.AND, 
                                               this.constraints, constraint);
        }
    }

    /**
     * Check if this parameter has external input dependencies
     */
    public boolean hasExternalInput() {
        if (parameterExpressions == null) {
            return false;
        }
        
        return parameterExpressions.getExpressions().stream()
            .anyMatch(expr -> {
                if (expr.isVariable()) {
                    Variable var = expr.getVariable();
                    return var instanceof InputVariable || 
                           (var instanceof MethodCallVariable && 
                            ((MethodCallVariable)var).toString().contains("getStringExtra"));
                }
                return false;
            });
    }

    /**
     * Check if this parameter is fully hard-coded (no external input)
     */
    public boolean isHardCoded() {
        if (parameterExpressions == null) {
            return false;
        }
        
        return parameterExpressions.getExpressions().stream()
            .allMatch(expr -> {
                if (expr.isVariable()) {
                    Variable var = expr.getVariable();
                    return var instanceof StringVariable;
                }
                return false;
            });
    }

    /**
     * Get a human-readable description of how this parameter is constructed
     */
    public String getConstructionDescription() {
        if (constructionComponents.isEmpty()) {
            return parameterValue.toString();
        }
        return String.join(" + ", constructionComponents);
    }
    
    // New getters and setters for path analysis
    public PathType getPathType() {
        return pathType;
    }
    
    public void setPathType(PathType pathType) {
        this.pathType = pathType;
    }
    
    public String getHardCodedValue() {
        return hardCodedValue;
    }
    
    public void setHardCodedValue(String value) {
        this.hardCodedValue = value;
    }
    
    public String getHardCodedPrefix() {
        return hardCodedPrefix;
    }
    
    public void setHardCodedPrefix(String prefix) {
        this.hardCodedPrefix = prefix;
    }
    
    public String getConstructionPattern() {
        return constructionPattern;
    }
    
    public void setConstructionPattern(String pattern) {
        this.constructionPattern = pattern;
    }
    
    public List<ExternalInputSource> getExternalInputSources() {
        return externalInputSources;
    }
    
    public void addExternalInputSource(ExternalInputSource source) {
        externalInputSources.add(source);
    }
    
    /**
     * Determine the path type based on expression analysis with taint tracking
     */
    public void determinePathType() {
        determinePathType(null);
    }
    
    /**
     * Determine the path type using taint analysis for enhanced accuracy
     */
    public void determinePathType(TaintTracker taintTracker) {
        if (parameterExpressions == null) {
            pathType = PathType.FULLY_CONTROLLED;
            return;
        }
        
        // If taint tracker is available, use it for more accurate classification
        if (taintTracker != null) {
            TaintTracker.TaintInfo.TaintType overallTaint = TaintTracker.TaintInfo.TaintType.CLEAN;
            
            for (Expression expr : parameterExpressions.getExpressions()) {
                if (expr.isVariable()) {
                    Variable var = expr.getVariable();
                    TaintTracker.TaintInfo taint = taintTracker.analyzeTaint(var);
                    
                    // Combine taint types - use most restrictive
                    if (taint.getTaintType() == TaintTracker.TaintInfo.TaintType.FULLY_TAINTED) {
                        if (overallTaint == TaintTracker.TaintInfo.TaintType.CLEAN) {
                            overallTaint = TaintTracker.TaintInfo.TaintType.PARTIALLY_TAINTED;
                        } else if (overallTaint == TaintTracker.TaintInfo.TaintType.PARTIALLY_TAINTED) {
                            overallTaint = TaintTracker.TaintInfo.TaintType.FULLY_TAINTED;
                        }
                    } else if (taint.getTaintType() == TaintTracker.TaintInfo.TaintType.PARTIALLY_TAINTED) {
                        if (overallTaint != TaintTracker.TaintInfo.TaintType.FULLY_TAINTED) {
                            overallTaint = TaintTracker.TaintInfo.TaintType.PARTIALLY_TAINTED;
                        }
                    }
                }
            }
            
            // Use taint tracker's classification
            pathType = taintTracker.classifyPathType(
                new TaintTracker.TaintInfo(overallTaint, null, "Combined parameter taint"));
            return;
        }
        
        // Fallback to original logic if no taint tracker
        boolean hasHardCoded = false;
        boolean hasExternal = false;
        
        for (Expression expr : parameterExpressions.getExpressions()) {
            if (expr.isVariable()) {
                Variable var = expr.getVariable();
                if (var instanceof StringVariable) {
                    hasHardCoded = true;
                } else if (var instanceof InputVariable || 
                           (var instanceof MethodCallVariable && 
                            ((MethodCallVariable)var).toString().contains("get"))) {
                    hasExternal = true;
                }
            } else if (expr.isStringExpression()) {
                // Handle string concatenation expressions
                StringExpression strExpr = (StringExpression) expr;
                if (containsHardCodedString(strExpr)) hasHardCoded = true;
                if (containsExternalInput(strExpr)) hasExternal = true;
            }
        }
        
        if (!hasExternal) {
            pathType = PathType.HARD_CODED;
        } else if (hasHardCoded) {
            pathType = PathType.PARTIALLY_CONTROLLED;
        } else {
            pathType = PathType.FULLY_CONTROLLED;
        }
    }
    
    private boolean containsHardCodedString(Expression expr) {
        if (expr.isVariable() && expr.getVariable() instanceof StringVariable) {
            return true;
        }
        if (expr.isStringExpression()) {
            StringExpression strExpr = (StringExpression) expr;
            return containsHardCodedString(strExpr.getLeft()) || 
                   containsHardCodedString(strExpr.getRight());
        }
        return false;
    }
    
    private boolean containsExternalInput(Expression expr) {
        if (expr.isVariable()) {
            Variable var = expr.getVariable();
            return var instanceof InputVariable || 
                   (var instanceof MethodCallVariable && 
                    ((MethodCallVariable)var).toString().contains("get"));
        }
        if (expr.isStringExpression()) {
            StringExpression strExpr = (StringExpression) expr;
            return containsExternalInput(strExpr.getLeft()) || 
                   containsExternalInput(strExpr.getRight());
        }
        return false;
    }

    @Override
    public String toString() {
        return String.format("StringParameter[method=%s, param=%d, type=%s, construction=%s]",
                           targetMethod.getSignature(), parameterIndex, pathType, getConstructionDescription());
    }
}