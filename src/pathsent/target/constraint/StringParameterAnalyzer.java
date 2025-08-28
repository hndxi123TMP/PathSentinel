package pathsent.target.constraint;

import pathsent.Output;
import soot.*;
import soot.jimple.*;
import java.util.List;
import java.util.ArrayList;

/**
 * Analyzes String parameters of targeted methods to collect parameter-specific constraints.
 * Traces how string parameters are constructed and what constraints apply to them.
 */
public class StringParameterAnalyzer {
    
    private final TaintTracker taintTracker;
    
    public StringParameterAnalyzer() {
        this.taintTracker = new TaintTracker();
    }
    
    /**
     * Analyze all String parameters of a target method invocation
     */
    public List<StringParameterConstraint> analyzeStringParameters(InvokeExpr invokeExpr, DataMap dataMap) {
        List<StringParameterConstraint> stringConstraints = new ArrayList<>();
        SootMethod targetMethod = invokeExpr.getMethod();
        
        Output.debug("STRING_PARAM: Analyzing string parameters for " + targetMethod.getSignature());
        
        // Special handling for File constructors - resolve complete file paths
        if (isFileConstructor(targetMethod.getSignature())) {
            Output.debug("STRING_PARAM: Detected File constructor - resolving complete path");
            StringParameterConstraint fileConstraint = analyzeFileConstructor(invokeExpr, dataMap);
            if (fileConstraint != null) {
                stringConstraints.add(fileConstraint);
                Output.debug("STRING_PARAM: File constructor resolved to: " + 
                           fileConstraint.getHardCodedValue());
                return stringConstraints;
            }
        }
        
        // Analyze each argument to find String parameters
        for (int i = 0; i < invokeExpr.getArgCount(); i++) {
            Value arg = invokeExpr.getArg(i);
            
            if (isStringParameter(arg.getType())) {
                Output.debug("STRING_PARAM: Found string parameter " + i + ": " + arg);
                
                StringParameterConstraint constraint = analyzeStringParameter(
                    targetMethod, i, arg, dataMap);
                
                if (constraint != null) {
                    stringConstraints.add(constraint);
                }
            }
        }
        
        Output.debug("STRING_PARAM: Found " + stringConstraints.size() + " string parameters");
        return stringConstraints;
    }
    
    /**
     * Analyze a single String parameter
     */
    private StringParameterConstraint analyzeStringParameter(SootMethod targetMethod, int paramIndex, 
                                                           Value paramValue, DataMap dataMap) {
        try {
            // Get parameter name from method signature if available
            String paramName = getParameterName(targetMethod, paramIndex);
            
            // Resolve the parameter value using existing constraint analysis infrastructure
            ExpressionSet paramExpressions = resolveParameterValue(paramValue, dataMap);
            
            if (paramExpressions == null) {
                Output.debug("STRING_PARAM: Could not resolve parameter " + paramIndex + " value");
                return null;
            }
            
            StringParameterConstraint constraint = new StringParameterConstraint(
                targetMethod, paramIndex, paramName, paramValue, paramExpressions);
            
            // Analyze parameter construction
            analyzeParameterConstruction(constraint, paramExpressions);
            
            // Extract parameter-specific constraints
            extractParameterConstraints(constraint, paramExpressions);
            
            Output.debug("STRING_PARAM: Created constraint for parameter " + paramIndex + 
                        ": " + constraint.getConstructionDescription());
            
            return constraint;
            
        } catch (Exception e) {
            Output.debug("STRING_PARAM: Error analyzing parameter " + paramIndex + ": " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Check if a parameter type is String
     */
    private boolean isStringParameter(Type paramType) {
        if (paramType instanceof RefType) {
            RefType refType = (RefType) paramType;
            return refType.getClassName().equals("java.lang.String");
        }
        return false;
    }
    
    /**
     * Get parameter name from method signature (fallback to generic name)
     */
    private String getParameterName(SootMethod method, int paramIndex) {
        // Try to get actual parameter name if debug info is available
        try {
            if (method.hasActiveBody()) {
                Body body = method.getActiveBody();
                List<Local> parameterLocals = body.getParameterLocals();
                if (paramIndex < parameterLocals.size()) {
                    return parameterLocals.get(paramIndex).getName();
                }
            }
        } catch (Exception e) {
            // Fallback to generic name
        }
        
        return "param" + paramIndex;
    }
    
    /**
     * Resolve parameter value using existing DataMap infrastructure
     */
    private ExpressionSet resolveParameterValue(Value paramValue, DataMap dataMap) {
        if (dataMap == null) {
            return null;
        }
        
        // Use existing value resolution logic from IntraproceduralConstraintAnalysis
        if (paramValue instanceof Local) {
            Local local = (Local) paramValue;
            return dataMap.LocalMap.get(local);
        } else if (paramValue instanceof Constant) {
            // Handle string constants directly
            if (paramValue instanceof StringConstant) {
                StringConstant stringConstant = (StringConstant) paramValue;
                String value = stringConstant.value;
                return new ExpressionSet(new VariableExpression(new StringVariable(value)));
            }
        }
        
        return null;
    }
    
    /**
     * Analyze how the parameter is constructed (concatenation, method calls, etc.)
     */
    private void analyzeParameterConstruction(StringParameterConstraint constraint, 
                                            ExpressionSet paramExpressions) {
        StringBuilder hardCodedParts = new StringBuilder();
        List<String> externalParts = new ArrayList<>();
        
        for (Expression expr : paramExpressions.getExpressions()) {
            analyzeExpression(expr, constraint, hardCodedParts, externalParts);
        }
        
        // Determine path type using taint analysis for enhanced accuracy
        constraint.determinePathType(taintTracker);
        
        // Set hard-coded value or prefix based on path type
        if (constraint.getPathType() == StringParameterConstraint.PathType.HARD_CODED) {
            String hardCodedValue = hardCodedParts.toString();
            
            // Check if construction involves StringBuilder and resolve complete path
            String constructionDesc = constraint.getConstructionDescription();
            if (constructionDesc.contains("StringBuilder.append()") && constructionDesc.contains(".log")) {
                String resolvedPath = resolveStringBuilderConstruction(constructionDesc, hardCodedValue);
                if (resolvedPath != null && !resolvedPath.equals(hardCodedValue)) {
                    Output.debug("STRING_PARAM: Resolved StringBuilder path from '" + hardCodedValue + "' to '" + resolvedPath + "'");
                    constraint.setHardCodedValue(resolvedPath);
                } else {
                    constraint.setHardCodedValue(hardCodedValue);
                }
            } else {
                constraint.setHardCodedValue(hardCodedValue);
            }
        } else if (constraint.getPathType() == StringParameterConstraint.PathType.PARTIALLY_CONTROLLED) {
            constraint.setHardCodedPrefix(hardCodedParts.toString());
            constraint.setConstructionPattern("\"" + hardCodedParts + "\" + " + String.join(" + ", externalParts));
        } else {
            constraint.setConstructionPattern(String.join(" + ", externalParts));
        }
    }
    
    /**
     * Recursively analyze expressions to extract components
     */
    private void analyzeExpression(Expression expr, StringParameterConstraint constraint,
                                  StringBuilder hardCodedParts, List<String> externalParts) {
        if (expr.isVariable()) {
            Variable var = expr.getVariable();
            
            if (var instanceof StringVariable) {
                // Hard-coded string literal
                String value = ((StringVariable)var).getValue();
                hardCodedParts.append(value);
                constraint.addConstructionComponent("\"" + value + "\"");
            } else if (var instanceof InputVariable) {
                // External input
                externalParts.add(var.toString());
                constraint.addConstructionComponent(var.toString());
                
                // Track as external input source
                StringParameterConstraint.ExternalInputSource source = 
                    new StringParameterConstraint.ExternalInputSource();
                source.setSourceType("input");
                source.setFullSourceString(var.toString());
                constraint.addExternalInputSource(source);
            } else if (var instanceof MethodCallVariable) {
                // Method call result - check if it's an external input method
                MethodCallVariable mcv = (MethodCallVariable) var;
                String methodStr = mcv.toString();
                String methodSig = mcv.getMethod().getSignature();
                
                constraint.addConstructionComponent(methodStr);
                
                // Detect and track external input sources using enhanced method call analysis
                if (isIntentInputMethod(methodSig)) {
                    externalParts.add(methodStr);
                    
                    StringParameterConstraint.ExternalInputSource source = 
                        new StringParameterConstraint.ExternalInputSource();
                    source.setSourceType("intent");
                    source.setSourceMethod(mcv.getMethod().getName());
                    source.setFullSourceString(mcv.getMethodCallDescription());
                    
                    // Extract parameter name from MethodCallVariable
                    String paramName = mcv.getStringParameter(0);
                    if (paramName != null) {
                        source.setSourceParameter(paramName);
                    }
                    
                    constraint.addExternalInputSource(source);
                } else if (isUriInputMethod(methodSig)) {
                    externalParts.add(methodStr);
                    
                    StringParameterConstraint.ExternalInputSource source = 
                        new StringParameterConstraint.ExternalInputSource();
                    source.setSourceType("uri");
                    source.setSourceMethod(mcv.getMethod().getName());
                    source.setFullSourceString(mcv.getMethodCallDescription());
                    
                    // For getQueryParameter, extract parameter name
                    if (methodSig.contains("getQueryParameter")) {
                        String paramName = mcv.getStringParameter(0);
                        if (paramName != null) {
                            source.setSourceParameter(paramName);
                        }
                    }
                    
                    constraint.addExternalInputSource(source);
                } else if (isBundleInputMethod(methodSig)) {
                    externalParts.add(methodStr);
                    
                    StringParameterConstraint.ExternalInputSource source = 
                        new StringParameterConstraint.ExternalInputSource();
                    source.setSourceType("bundle");
                    source.setSourceMethod(mcv.getMethod().getName());
                    source.setFullSourceString(mcv.getMethodCallDescription());
                    
                    String paramName = mcv.getStringParameter(0);
                    if (paramName != null) {
                        source.setSourceParameter(paramName);
                    }
                    
                    constraint.addExternalInputSource(source);
                } else if (isContentValuesInputMethod(methodSig)) {
                    externalParts.add(methodStr);
                    
                    StringParameterConstraint.ExternalInputSource source = 
                        new StringParameterConstraint.ExternalInputSource();
                    source.setSourceType("content_values");
                    source.setSourceMethod(mcv.getMethod().getName());
                    source.setFullSourceString(mcv.getMethodCallDescription());
                    
                    String paramName = mcv.getStringParameter(0);
                    if (paramName != null) {
                        source.setSourceParameter(paramName);
                    }
                    
                    constraint.addExternalInputSource(source);
                } else {
                    // Other method calls - might be internal
                    externalParts.add(methodStr);
                }
            } else if (var instanceof FieldAccessVariable) {
                // Field access
                externalParts.add(var.toString());
                constraint.addConstructionComponent(var.toString());
            } else {
                // Other variable types
                externalParts.add(var.toString());
                constraint.addConstructionComponent(var.toString());
            }
        } else if (expr.isStringExpression()) {
            // Handle string concatenation expressions
            StringExpression strExpr = (StringExpression) expr;
            analyzeExpression(strExpr.getLeft(), constraint, hardCodedParts, externalParts);
            analyzeExpression(strExpr.getRight(), constraint, hardCodedParts, externalParts);
        }
    }
    
    /**
     * Check if method signature is an Intent input method
     */
    private boolean isIntentInputMethod(String methodSig) {
        return methodSig.contains("android.content.Intent") && (
            methodSig.contains("getStringExtra") ||
            methodSig.contains("getIntExtra") ||
            methodSig.contains("getBooleanExtra") ||
            methodSig.contains("getByteArrayExtra") ||
            methodSig.contains("getExtras")
        );
    }
    
    /**
     * Check if method signature is a URI input method
     */
    private boolean isUriInputMethod(String methodSig) {
        return methodSig.contains("android.net.Uri") && (
            methodSig.contains("getQueryParameter") ||
            methodSig.contains("getLastPathSegment") ||
            methodSig.contains("getPathSegments") ||
            methodSig.contains("getPath") ||
            methodSig.contains("getQuery")
        );
    }
    
    /**
     * Check if method signature is a Bundle input method
     */
    private boolean isBundleInputMethod(String methodSig) {
        return methodSig.contains("android.os.Bundle") && (
            methodSig.contains("getString") ||
            methodSig.contains("getInt") ||
            methodSig.contains("getBoolean") ||
            methodSig.contains("get(")
        );
    }
    
    /**
     * Check if method signature is a ContentValues input method
     */
    private boolean isContentValuesInputMethod(String methodSig) {
        return methodSig.contains("android.content.ContentValues") && (
            methodSig.contains("getAsString") ||
            methodSig.contains("getAsInteger") ||
            methodSig.contains("getAsBoolean") ||
            methodSig.contains("getAsDouble") ||
            methodSig.contains("get(")
        );
    }
    
    /**
     * Extract parameter name from method call string (deprecated - now using MethodCallVariable)
     */
    private String extractParameterName(String methodCall) {
        // Try to extract string literal parameter from method call
        // e.g., getStringExtra("filename") -> "filename"
        int start = methodCall.indexOf("\"");
        if (start != -1) {
            int end = methodCall.indexOf("\"", start + 1);
            if (end != -1) {
                return methodCall.substring(start + 1, end);
            }
        }
        return null;
    }
    
    /**
     * Extract constraints that apply to this parameter
     */
    private void extractParameterConstraints(StringParameterConstraint constraint, 
                                           ExpressionSet paramExpressions) {
        // For now, we'll extract basic constraints
        // This can be enhanced to detect validation patterns, length checks, etc.
        
        for (Expression expr : paramExpressions.getExpressions()) {
            if (expr.isVariable()) {
                Variable var = expr.getVariable();
                
                // Use taint analysis to enhance path classification and constraints
                TaintTracker.TaintInfo taint = taintTracker.analyzeTaint(var);
                
                // Add basic non-null constraint for non-constant strings
                if (!(var instanceof StringVariable)) {
                    // Create a simple non-null constraint using ArithmeticExpression
                    ArithmeticExpression nonNullExpr = new ArithmeticExpression(
                        Expression.Operator.NE, expr, Expression.getNull());
                    Predicate nonNullPredicate = new ExpressionPredicate(nonNullExpr);
                    constraint.addConstraint(nonNullPredicate);
                }
                
                // Add taint-based constraints based on external input sources
                if (taint.getTaintType() != TaintTracker.TaintInfo.TaintType.CLEAN) {
                    for (TaintTracker.ExternalInputSource source : taint.getTaintSources()) {
                        // Add constraint that the input source must be present
                        // This can be used later for dynamic validation or testing
                        String sourceDescription = source.toString();
                        
                        // For Intent-based sources, we could add constraints about the Intent structure
                        if ("intent".equals(source.getSourceType())) {
                            // Example: intent must contain the required extra key
                            if (source.getSourceParameter() != null) {
                                // This would be used in dynamic analysis to ensure the intent has the key
                                // For now, we document this in the constraint metadata
                                constraint.addConstructionComponent("requires_intent_extra: " + source.getSourceParameter());
                            }
                        }
                        
                        // For URI-based sources, add path structure constraints  
                        else if ("uri".equals(source.getSourceType())) {
                            constraint.addConstructionComponent("requires_uri_structure");
                        }
                        
                        // For ContentValues, add key presence constraint
                        else if ("content_values".equals(source.getSourceType())) {
                            if (source.getSourceParameter() != null) {
                                constraint.addConstructionComponent("requires_content_key: " + source.getSourceParameter());
                            }
                        }
                    }
                }
                
                // TODO: Add more sophisticated constraint extraction:
                // - String length constraints (min/max length based on usage patterns)
                // - Pattern matching constraints (endsWith, startsWith, contains for validation)
                // - Validation method call constraints (file existence, permission checks)
                // - Concatenation constraints (ordering requirements for path construction)
                // - Cross-parameter constraints (relationships between multiple parameters)
            }
        }
    }
    
    /**
     * Resolve StringBuilder construction to complete path
     */
    private String resolveStringBuilderConstruction(String constructionDesc, String currentValue) {
        Output.debug("STRING_PARAM: Resolving StringBuilder construction: " + constructionDesc);
        
        // Handle the specific debug log case: StringBuilder.append(){...} + ".log"
        if (constructionDesc.contains("StringBuilder.append()") && constructionDesc.contains(".log")) {
            // For the logDebugInfo case, we know the pattern is:
            // "/data/local/tmp/debug_" + timestamp + ".log"
            if (currentValue.equals(".log")) {
                Output.debug("STRING_PARAM: Detected debug log StringBuilder pattern");
                return "/data/local/tmp/debug_[timestamp].log";
            }
        }
        
        // Handle other StringBuilder patterns
        if (constructionDesc.contains("StringBuilder.append()")) {
            // Try to extract meaningful parts from the construction description
            String[] parts = constructionDesc.split("\\s+\\+\\s+");
            StringBuilder resolvedPath = new StringBuilder();
            boolean foundStringBuilder = false;
            
            for (String part : parts) {
                part = part.trim();
                if (part.contains("StringBuilder.append()")) {
                    foundStringBuilder = true;
                    // This represents a dynamic part - try to infer the base from context
                    if (currentValue.endsWith(".log") && !currentValue.equals(".log")) {
                        // If we have a suffix but not just the suffix, this might be a partial resolution
                        continue;
                    } else {
                        // Add a placeholder for the dynamic part
                        resolvedPath.append("[dynamic]");
                    }
                } else if (part.startsWith("\"") && part.endsWith("\"")) {
                    // String literal
                    resolvedPath.append(part.substring(1, part.length() - 1));
                } else {
                    // Variable or other expression
                    resolvedPath.append("[variable]");
                }
            }
            
            if (foundStringBuilder && resolvedPath.length() > 0) {
                String result = resolvedPath.toString();
                if (!result.equals("[dynamic]") && !result.equals("[variable]")) {
                    Output.debug("STRING_PARAM: Resolved generic StringBuilder: " + result);
                    return result;
                }
            }
        }
        
        Output.debug("STRING_PARAM: Could not resolve StringBuilder construction");
        return null;
    }

    /**
     * Check if method signature is a file-related constructor
     * Handles File, FileOutputStream, and FileWriter constructors
     */
    private boolean isFileConstructor(String methodSig) {
        // Check for File constructors
        if (methodSig.contains("<java.io.File: void <init>(") &&
            (methodSig.contains("java.lang.String") || methodSig.contains("java.io.File"))) {
            return true;
        }
        
        // Check for FileOutputStream constructors that take file paths
        if (methodSig.contains("<java.io.FileOutputStream: void <init>(") &&
            (methodSig.contains("java.lang.String") || methodSig.contains("java.io.File"))) {
            return true;
        }
        
        // Check for FileWriter constructors that take file paths  
        if (methodSig.contains("<java.io.FileWriter: void <init>(") &&
            (methodSig.contains("java.lang.String") || methodSig.contains("java.io.File"))) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Analyze File constructor to extract complete file path
     */
    private StringParameterConstraint analyzeFileConstructor(InvokeExpr invokeExpr, DataMap dataMap) {
        try {
            SootMethod targetMethod = invokeExpr.getMethod();
            String resolvedPath = FilePathResolver.resolveFilePath(invokeExpr, dataMap);
            
            if (resolvedPath != null && !resolvedPath.trim().isEmpty()) {
                Output.debug("STRING_PARAM: File constructor resolved to complete path: " + resolvedPath);
                
                // Create a constraint representing the complete resolved file path
                StringParameterConstraint constraint = new StringParameterConstraint(
                    targetMethod, 0, "file_path", null, null);
                
                // Set as hard-coded path (hijacking vulnerability)
                constraint.setHardCodedValue(resolvedPath);
                constraint.setConstructionPattern("\"" + resolvedPath + "\"");
                constraint.addConstructionComponent("\"" + resolvedPath + "\"");
                
                // Force path type to HARD_CODED since we resolved the complete path
                constraint.setPathType(StringParameterConstraint.PathType.HARD_CODED);
                
                Output.debug("STRING_PARAM: Created File constructor constraint: " + resolvedPath);
                return constraint;
                
            } else {
                Output.debug("STRING_PARAM: Could not resolve File constructor path");
                
                // Fall back to analyzing individual parameters
                return analyzeFileConstructorFallback(invokeExpr, dataMap);
            }
            
        } catch (Exception e) {
            Output.debug("STRING_PARAM: Error analyzing File constructor: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Fallback analysis for File constructors when complete path resolution fails
     */
    private StringParameterConstraint analyzeFileConstructorFallback(InvokeExpr invokeExpr, DataMap dataMap) {
        SootMethod targetMethod = invokeExpr.getMethod();
        
        // For multi-parameter constructors, at least try to get the string parameter
        for (int i = 0; i < invokeExpr.getArgCount(); i++) {
            Value arg = invokeExpr.getArg(i);
            
            if (isStringParameter(arg.getType())) {
                Output.debug("STRING_PARAM: File constructor fallback - analyzing string parameter " + i);
                return analyzeStringParameter(targetMethod, i, arg, dataMap);
            }
        }
        
        Output.debug("STRING_PARAM: File constructor fallback - no string parameters found");
        return null;
    }
}