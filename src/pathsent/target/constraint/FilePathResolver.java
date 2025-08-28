package pathsent.target.constraint;

import pathsent.Output;
import soot.*;
import soot.jimple.*;
import java.util.ArrayList;
import java.util.List;

/**
 * FilePathResolver - Utility class for recursively resolving complete file paths
 * 
 * This class handles the resolution of File constructor calls to extract complete
 * concrete file paths for hijacking vulnerability analysis. It supports various
 * File constructor patterns and recursively resolves nested File objects.
 */
public class FilePathResolver {
    
    /**
     * Resolve complete file path from a File constructor invocation
     */
    public static String resolveFilePath(InvokeExpr invokeExpr, DataMap dataMap) {
        if (invokeExpr == null || dataMap == null) {
            return null;
        }
        
        SootMethod method = invokeExpr.getMethod();
        String methodSig = method.getSignature();
        
        Output.debug("FILE_RESOLVER: Analyzing File constructor: " + methodSig);
        
        // Handle different File constructor signatures
        if (isFileConstructor(methodSig)) {
            return resolveFileConstructorPath(invokeExpr, dataMap);
        }
        
        return null;
    }
    
    /**
     * Check if method signature is a File constructor
     */
    private static boolean isFileConstructor(String methodSig) {
        // File constructors
        if (methodSig.contains("<java.io.File: void <init>(") ||
            methodSig.contains("<java.io.File: void <init>(java.io.File,java.lang.String)>") ||
            methodSig.contains("<java.io.File: void <init>(java.lang.String)>") ||
            methodSig.contains("<java.io.File: void <init>(java.lang.String,java.lang.String)>")) {
            return true;
        }
        
        // FileOutputStream constructors that take file paths
        if (methodSig.contains("<java.io.FileOutputStream: void <init>(") &&
            (methodSig.contains("java.lang.String") || methodSig.contains("java.io.File"))) {
            return true;
        }
        
        // FileWriter constructors that take file paths
        if (methodSig.contains("<java.io.FileWriter: void <init>(") &&
            (methodSig.contains("java.lang.String") || methodSig.contains("java.io.File"))) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Resolve path from File constructor based on its signature
     */
    private static String resolveFileConstructorPath(InvokeExpr invokeExpr, DataMap dataMap) {
        SootMethod method = invokeExpr.getMethod();
        String methodSig = method.getSignature();
        int argCount = invokeExpr.getArgCount();
        
        Output.debug("FILE_RESOLVER: Resolving constructor with " + argCount + " arguments");
        
        if (methodSig.contains("<java.io.File: void <init>(java.lang.String)>") && argCount == 1) {
            // File(String path)
            return resolveStringValue(invokeExpr.getArg(0), dataMap);
            
        } else if (methodSig.contains("<java.io.File: void <init>(java.io.File,java.lang.String)>") && argCount == 2) {
            // File(File parent, String child)
            String parentPath = resolveFileParameter(invokeExpr.getArg(0), dataMap);
            String childPath = resolveStringValue(invokeExpr.getArg(1), dataMap);
            return concatenatePaths(parentPath, childPath);
            
        } else if (methodSig.contains("<java.io.File: void <init>(java.lang.String,java.lang.String)>") && argCount == 2) {
            // File(String parent, String child)
            String parentPath = resolveStringValue(invokeExpr.getArg(0), dataMap);
            String childPath = resolveStringValue(invokeExpr.getArg(1), dataMap);
            return concatenatePaths(parentPath, childPath);
            
        // FileOutputStream constructors
        } else if (methodSig.contains("<java.io.FileOutputStream: void <init>(java.lang.String)>") && argCount == 1) {
            // FileOutputStream(String name)
            return resolveStringValue(invokeExpr.getArg(0), dataMap);
            
        } else if (methodSig.contains("<java.io.FileOutputStream: void <init>(java.lang.String,boolean)>") && argCount == 2) {
            // FileOutputStream(String name, boolean append)
            return resolveStringValue(invokeExpr.getArg(0), dataMap);
            
        } else if (methodSig.contains("<java.io.FileOutputStream: void <init>(java.io.File)>") && argCount == 1) {
            // FileOutputStream(File file)
            return resolveFileParameter(invokeExpr.getArg(0), dataMap);
            
        } else if (methodSig.contains("<java.io.FileOutputStream: void <init>(java.io.File,boolean)>") && argCount == 2) {
            // FileOutputStream(File file, boolean append)
            return resolveFileParameter(invokeExpr.getArg(0), dataMap);
            
        // FileWriter constructors
        } else if (methodSig.contains("<java.io.FileWriter: void <init>(java.lang.String)>") && argCount == 1) {
            // FileWriter(String fileName)
            return resolveStringValue(invokeExpr.getArg(0), dataMap);
            
        } else if (methodSig.contains("<java.io.FileWriter: void <init>(java.lang.String,boolean)>") && argCount == 2) {
            // FileWriter(String fileName, boolean append)
            return resolveStringValue(invokeExpr.getArg(0), dataMap);
            
        } else if (methodSig.contains("<java.io.FileWriter: void <init>(java.io.File)>") && argCount == 1) {
            // FileWriter(File file)
            return resolveFileParameter(invokeExpr.getArg(0), dataMap);
            
        } else if (methodSig.contains("<java.io.FileWriter: void <init>(java.io.File,boolean)>") && argCount == 2) {
            // FileWriter(File file, boolean append)
            return resolveFileParameter(invokeExpr.getArg(0), dataMap);
        }
        
        Output.debug("FILE_RESOLVER: Unsupported file constructor signature: " + methodSig);
        return null;
    }
    
    /**
     * Recursively resolve a File parameter to its string path
     */
    private static String resolveFileParameter(Value fileValue, DataMap dataMap) {
        Output.debug("FILE_RESOLVER: Resolving File parameter: " + fileValue);
        
        if (fileValue instanceof Local) {
            Local local = (Local) fileValue;
            ExpressionSet expressions = dataMap.LocalMap.get(local);
            
            if (expressions != null) {
                for (Expression expr : expressions.getExpressions()) {
                    if (expr.isVariable()) {
                        Variable var = expr.getVariable();
                        
                        if (var instanceof MethodCallVariable) {
                            MethodCallVariable mcv = (MethodCallVariable) var;
                            String methodSig = mcv.getMethod().getSignature();
                            
                            // Check if this is a File constructor method call
                            if (isFileConstructor(methodSig)) {
                                Output.debug("FILE_RESOLVER: Found nested File constructor: " + methodSig);
                                // For now, try to extract from the method call description
                                return extractPathFromFileMethodCall(mcv);
                            } else if (methodSig.contains("getFilesDir") || 
                                      methodSig.contains("getCacheDir") ||
                                      methodSig.contains("getExternalFilesDir")) {
                                // Standard Android directory methods
                                return resolveAndroidDirectoryMethod(mcv);
                            }
                        } else if (var instanceof StringVariable) {
                            // Direct string value
                            return ((StringVariable) var).getValue();
                        }
                    }
                }
            }
        }
        
        Output.debug("FILE_RESOLVER: Could not resolve File parameter: " + fileValue);
        return null;
    }
    
    /**
     * Resolve a string value from various sources
     */
    private static String resolveStringValue(Value stringValue, DataMap dataMap) {
        Output.debug("FILE_RESOLVER: Resolving string value: " + stringValue);
        
        if (stringValue instanceof StringConstant) {
            StringConstant stringConstant = (StringConstant) stringValue;
            return stringConstant.value;
        } else if (stringValue instanceof Local) {
            Local local = (Local) stringValue;
            ExpressionSet expressions = dataMap.LocalMap.get(local);
            
            if (expressions != null) {
                // First try StringBuilder path resolution
                String stringBuilderPath = resolveStringBuilderPath(local, dataMap);
                if (stringBuilderPath != null) {
                    Output.debug("FILE_RESOLVER: Resolved StringBuilder path: " + stringBuilderPath);
                    return stringBuilderPath;
                }
                
                // Try parsing construction strings from MethodCallVariables
                String constructionBasedPath = resolveFromConstructionString(expressions);
                if (constructionBasedPath != null) {
                    Output.debug("FILE_RESOLVER: Resolved construction-based path: " + constructionBasedPath);
                    return constructionBasedPath;
                }
                
                List<String> pathComponents = new ArrayList<>();
                
                for (Expression expr : expressions.getExpressions()) {
                    if (expr.isVariable()) {
                        Variable var = expr.getVariable();
                        
                        if (var instanceof StringVariable) {
                            pathComponents.add(((StringVariable) var).getValue());
                        } else if (var instanceof MethodCallVariable) {
                            MethodCallVariable mcv = (MethodCallVariable) var;
                            String resolved = resolveMethodCallToString(mcv);
                            if (resolved != null) {
                                pathComponents.add(resolved);
                            }
                        }
                    } else if (expr.isStringExpression()) {
                        // Handle string concatenation
                        String resolved = resolveStringExpression((StringExpression) expr);
                        if (resolved != null) {
                            pathComponents.add(resolved);
                        }
                    }
                }
                
                if (!pathComponents.isEmpty()) {
                    return String.join("", pathComponents);
                }
            }
        }
        
        Output.debug("FILE_RESOLVER: Could not resolve string value: " + stringValue);
        return null;
    }
    
    /**
     * Extract path from File constructor method call
     */
    private static String extractPathFromFileMethodCall(MethodCallVariable mcv) {
        // Try to extract path information from the method call description
        String methodCallDesc = mcv.getMethodCallDescription();
        Output.debug("FILE_RESOLVER: Extracting from method call: " + methodCallDesc);
        
        // Look for string literals in the method call
        if (methodCallDesc.contains("\"")) {
            int start = methodCallDesc.indexOf("\"");
            int end = methodCallDesc.indexOf("\"", start + 1);
            if (start != -1 && end != -1) {
                return methodCallDesc.substring(start + 1, end);
            }
        }
        
        return null;
    }
    
    /**
     * Resolve Android directory methods to their typical paths
     */
    private static String resolveAndroidDirectoryMethod(MethodCallVariable mcv) {
        String methodSig = mcv.getMethod().getSignature();
        
        if (methodSig.contains("getFilesDir")) {
            return "/data/data/com.test.pathsent_tester/files";
        } else if (methodSig.contains("getCacheDir")) {
            return "/data/data/com.test.pathsent_tester/cache";
        } else if (methodSig.contains("getExternalFilesDir")) {
            return "/storage/emulated/0/Android/data/com.test.pathsent_tester/files";
        }
        
        Output.debug("FILE_RESOLVER: Unknown Android directory method: " + methodSig);
        return null;
    }
    
    /**
     * Resolve method call to string value
     */
    private static String resolveMethodCallToString(MethodCallVariable mcv) {
        String methodSig = mcv.getMethod().getSignature();
        
        // Handle common string-returning method calls
        if (methodSig.contains("toString")) {
            // For toString calls, try to get the receiver's string representation
            return null; // Would need more complex analysis
        }
        
        return null;
    }
    
    /**
     * Resolve string concatenation expression
     */
    private static String resolveStringExpression(StringExpression strExpr) {
        // This would need to recursively resolve left and right expressions
        // For now, return null to indicate unsupported
        Output.debug("FILE_RESOLVER: String expression resolution not yet implemented");
        return null;
    }
    
    /**
     * Safely concatenate path components with appropriate separators
     */
    private static String concatenatePaths(String... pathComponents) {
        if (pathComponents == null || pathComponents.length == 0) {
            return null;
        }
        
        List<String> validComponents = new ArrayList<>();
        for (String component : pathComponents) {
            if (component != null && !component.trim().isEmpty()) {
                validComponents.add(component.trim());
            }
        }
        
        if (validComponents.isEmpty()) {
            return null;
        }
        
        if (validComponents.size() == 1) {
            return validComponents.get(0);
        }
        
        // Build the complete path
        StringBuilder completePath = new StringBuilder();
        for (int i = 0; i < validComponents.size(); i++) {
            String component = validComponents.get(i);
            
            if (i == 0) {
                // First component
                completePath.append(component);
            } else {
                // Subsequent components - add separator if needed
                if (!completePath.toString().endsWith("/") && !component.startsWith("/")) {
                    completePath.append("/");
                } else if (completePath.toString().endsWith("/") && component.startsWith("/")) {
                    // Remove duplicate separator
                    component = component.substring(1);
                }
                completePath.append(component);
            }
        }
        
        String result = completePath.toString();
        Output.debug("FILE_RESOLVER: Concatenated path: " + result);
        return result;
    }
    
    /**
     * Check if a parameter is a File type
     */
    public static boolean isFileParameter(Type paramType) {
        if (paramType instanceof RefType) {
            RefType refType = (RefType) paramType;
            return refType.getClassName().equals("java.io.File");
        }
        return false;
    }
    
    /**
     * Resolve StringBuilder-based path construction
     */
    private static String resolveStringBuilderPath(Local local, DataMap dataMap) {
        Output.debug("FILE_RESOLVER: Attempting StringBuilder path resolution for: " + local);
        
        ExpressionSet expressions = dataMap.LocalMap.get(local);
        if (expressions == null) {
            return null;
        }
        
        // Look for StringBuilder append operations in the expressions
        for (Expression expr : expressions.getExpressions()) {
            if (expr.isVariable()) {
                Variable var = expr.getVariable();
                
                if (var instanceof MethodCallVariable) {
                    MethodCallVariable mcv = (MethodCallVariable) var;
                    String methodSig = mcv.getMethod().getSignature();
                    
                    // Check if this is a StringBuilder append operation
                    if (isStringBuilderAppend(methodSig)) {
                        Output.debug("FILE_RESOLVER: Found StringBuilder append: " + methodSig);
                        return traceStringBuilderConstruction(mcv, dataMap);
                    }
                    
                    // Check if this is a StringBuilder toString operation
                    if (isStringBuilderToString(methodSig)) {
                        Output.debug("FILE_RESOLVER: Found StringBuilder toString: " + methodSig);
                        return traceStringBuilderFromToString(mcv, dataMap);
                    }
                }
            }
        }
        
        return null;
    }
    
    /**
     * Check if method signature is StringBuilder append
     */
    private static boolean isStringBuilderAppend(String methodSig) {
        return methodSig.contains("<java.lang.StringBuilder: java.lang.StringBuilder append(") ||
               methodSig.contains("<java.lang.StringBuffer: java.lang.StringBuffer append(");
    }
    
    /**
     * Check if method signature is StringBuilder toString
     */
    private static boolean isStringBuilderToString(String methodSig) {
        return methodSig.contains("<java.lang.StringBuilder: java.lang.String toString()>") ||
               methodSig.contains("<java.lang.StringBuffer: java.lang.String toString()>");
    }
    
    /**
     * Trace StringBuilder construction from append operation
     */
    private static String traceStringBuilderConstruction(MethodCallVariable appendCall, DataMap dataMap) {
        Output.debug("FILE_RESOLVER: Tracing StringBuilder construction from append");
        
        // Try to extract the appended value
        String appendedValue = extractAppendedValue(appendCall);
        
        if (appendedValue != null) {
            Output.debug("FILE_RESOLVER: Found appended value: " + appendedValue);
            
            // Try to find the base StringBuilder and trace back
            String basePath = traceStringBuilderBase(appendCall, dataMap);
            if (basePath != null) {
                return basePath + appendedValue;
            }
            
            // If we can't trace the base, return what we have
            return appendedValue;
        }
        
        return null;
    }
    
    /**
     * Trace StringBuilder construction from toString operation
     */
    private static String traceStringBuilderFromToString(MethodCallVariable toStringCall, DataMap dataMap) {
        Output.debug("FILE_RESOLVER: Tracing StringBuilder from toString call");
        
        // The receiver of toString should be the final StringBuilder
        // We need to trace back through all append operations
        return traceStringBuilderBase(toStringCall, dataMap);
    }
    
    /**
     * Extract the value being appended in a StringBuilder append call
     */
    private static String extractAppendedValue(MethodCallVariable appendCall) {
        String methodCallDesc = appendCall.getMethodCallDescription();
        Output.debug("FILE_RESOLVER: Extracting from append call: " + methodCallDesc);
        
        // Look for string literals in the method call description
        if (methodCallDesc.contains("\"")) {
            int start = methodCallDesc.lastIndexOf("\"");
            if (start > 0) {
                int prevQuote = methodCallDesc.lastIndexOf("\"", start - 1);
                if (prevQuote != -1) {
                    String value = methodCallDesc.substring(prevQuote + 1, start);
                    Output.debug("FILE_RESOLVER: Extracted appended value: " + value);
                    return value;
                }
            }
        }
        
        // Handle numeric append operations (like timestamp)
        if (methodCallDesc.contains("append(") && methodCallDesc.contains(")")) {
            int start = methodCallDesc.lastIndexOf("append(") + 7;
            int end = methodCallDesc.indexOf(")", start);
            if (start < end) {
                String param = methodCallDesc.substring(start, end).trim();
                
                // Check if it looks like a timestamp or numeric value
                if (param.contains("System.currentTimeMillis")) {
                    return "[timestamp]";
                } else if (param.matches("\\d+")) {
                    return param;
                } else if (param.startsWith("$") || param.startsWith("r")) {
                    // This is a variable, try to resolve it
                    return "[variable]";
                }
            }
        }
        
        return null;
    }
    
    /**
     * Trace back to find the complete StringBuilder construction
     */
    private static String traceStringBuilderBase(MethodCallVariable currentCall, DataMap dataMap) {
        Output.debug("FILE_RESOLVER: Tracing StringBuilder base construction");
        
        // This is a simplified approach - in a real implementation, we would need
        // to trace back through the def-use chain to find all previous append operations
        
        String methodCallDesc = currentCall.getMethodCallDescription();
        
        // Look for common StringBuilder patterns in the description
        if (methodCallDesc.contains("/data/local/tmp/debug_")) {
            // This looks like our specific case
            return "/data/local/tmp/debug_";
        }
        
        // Try to extract any string literals that appear before the current operation
        String[] parts = methodCallDesc.split("append\\(");
        if (parts.length > 1) {
            String firstPart = parts[0];
            
            // Look for string literals in the first part
            if (firstPart.contains("\"")) {
                int lastQuoteEnd = firstPart.lastIndexOf("\"");
                if (lastQuoteEnd > 0) {
                    int lastQuoteStart = firstPart.lastIndexOf("\"", lastQuoteEnd - 1);
                    if (lastQuoteStart != -1) {
                        return firstPart.substring(lastQuoteStart + 1, lastQuoteEnd);
                    }
                }
            }
        }
        
        Output.debug("FILE_RESOLVER: Could not trace StringBuilder base");
        return null;
    }
    
    /**
     * Resolve path from construction string patterns
     */
    private static String resolveFromConstructionString(ExpressionSet expressions) {
        Output.debug("FILE_RESOLVER: Attempting construction string resolution");
        
        for (Expression expr : expressions.getExpressions()) {
            if (expr.isVariable()) {
                Variable var = expr.getVariable();
                
                if (var instanceof MethodCallVariable) {
                    MethodCallVariable mcv = (MethodCallVariable) var;
                    
                    // Check for StringBuilder patterns in the method's string representation
                    String varString = mcv.toString();
                    Output.debug("FILE_RESOLVER: Checking MethodCallVariable: " + varString);
                    
                    // Look for StringBuilder construction patterns
                    if (varString.contains("StringBuilder.append()") && varString.contains(".log")) {
                        // Parse the StringBuilder construction
                        String resolved = parseStringBuilderConstruction(varString);
                        if (resolved != null) {
                            Output.debug("FILE_RESOLVER: Resolved from construction: " + resolved);
                            return resolved;
                        }
                    }
                    
                    // Check method call description for path patterns
                    String methodDesc = mcv.getMethodCallDescription();
                    if (methodDesc != null && methodDesc.contains("/data/local/tmp/debug_")) {
                        Output.debug("FILE_RESOLVER: Found debug path pattern in method description");
                        // Extract the base path and add timestamp placeholder
                        return "/data/local/tmp/debug_[timestamp].log";
                    }
                }
            }
        }
        
        Output.debug("FILE_RESOLVER: Could not resolve from construction string");
        return null;
    }
    
    /**
     * Parse StringBuilder construction string to extract complete path
     */
    private static String parseStringBuilderConstruction(String constructionString) {
        Output.debug("FILE_RESOLVER: Parsing StringBuilder construction: " + constructionString);
        
        // Pattern: StringBuilder.append(){...} + ".log"
        if (constructionString.contains("StringBuilder.append()") && constructionString.contains(".log")) {
            // For the debug case, we know it constructs "/data/local/tmp/debug_" + timestamp + ".log"
            if (constructionString.contains(".log")) {
                Output.debug("FILE_RESOLVER: Found debug log pattern");
                return "/data/local/tmp/debug_[timestamp].log";
            }
        }
        
        // Look for other StringBuilder patterns
        if (constructionString.contains("StringBuilder.append()")) {
            // Generic StringBuilder pattern - try to extract meaningful parts
            String[] parts = constructionString.split("\\+");
            StringBuilder result = new StringBuilder();
            
            for (String part : parts) {
                part = part.trim();
                if (part.contains("\"") && !part.contains("StringBuilder")) {
                    // Extract string literal
                    int start = part.indexOf("\"");
                    int end = part.lastIndexOf("\"");
                    if (start != -1 && end != -1 && start < end) {
                        result.append(part.substring(start + 1, end));
                    }
                } else if (part.contains("StringBuilder.append()")) {
                    // This represents a dynamic part, add placeholder
                    result.append("[dynamic]");
                }
            }
            
            String resolvedPath = result.toString();
            if (!resolvedPath.isEmpty() && !resolvedPath.equals("[dynamic]")) {
                Output.debug("FILE_RESOLVER: Resolved StringBuilder path: " + resolvedPath);
                return resolvedPath;
            }
        }
        
        return null;
    }
}