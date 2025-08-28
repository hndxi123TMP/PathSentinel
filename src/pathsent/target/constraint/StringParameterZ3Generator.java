package pathsent.target.constraint;

import pathsent.Output;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import java.util.*;

/**
 * Generates Z3 constraint code specifically for String parameter constraints.
 * Creates separate constraint files for string parameters alongside control flow constraints.
 */
public class StringParameterZ3Generator {
    private final List<StringParameterConstraint> _stringConstraints;
    private final Map<StringParameterConstraint, String> _parameterVariableMap = new LinkedHashMap<>();
    private int _nextVariableNum = 0;

    public StringParameterZ3Generator(List<StringParameterConstraint> stringConstraints) {
        _stringConstraints = stringConstraints;
        generateVariableMap();
    }

    /**
     * Generate appropriate output based on path type
     * For HARD_CODED: returns plain text path
     * For PARTIALLY_CONTROLLED and FULLY_CONTROLLED: returns Z3 constraints
     */
    public String generatePathConstraints() {
        if (_stringConstraints.isEmpty()) {
            return "# No path constraints\n";
        }
        
        // Check if all constraints are hard-coded (for hijacking)
        boolean allHardCoded = _stringConstraints.stream()
            .allMatch(c -> c.getPathType() == StringParameterConstraint.PathType.HARD_CODED);
        
        if (allHardCoded) {
            // For hijacking vulnerabilities, return plain text paths
            return generateHardCodedPaths();
        } else {
            // For traversal vulnerabilities, return Z3 constraints
            return generateZ3PathConstraints();
        }
    }
    
    /**
     * Generate plain text output for hard-coded paths (hijacking)
     */
    private String generateHardCodedPaths() {
        StringBuilder paths = new StringBuilder();
        
        for (StringParameterConstraint constraint : _stringConstraints) {
            if (constraint.getHardCodedValue() != null) {
                String hardCodedPath = constraint.getHardCodedValue();
                paths.append("path = ").append(hardCodedPath).append("\n");
                
                // Add debug comment if this was resolved from a File constructor
                if (isCompleteResolvedPath(hardCodedPath)) {
                    paths.append("# Complete path resolved from File constructor").append("\n");
                }
            } else if (constraint.isHardCoded() && !constraint.getConstructionComponents().isEmpty()) {
                // Extract hard-coded value from construction components
                String value = extractHardCodedValue(constraint);
                if (value != null) {
                    paths.append("path = ").append(value).append("\n");
                }
            }
        }
        
        return paths.toString();
    }
    
    /**
     * Extract hard-coded value from construction components
     */
    private String extractHardCodedValue(StringParameterConstraint constraint) {
        StringBuilder value = new StringBuilder();
        for (String component : constraint.getConstructionComponents()) {
            if (component.startsWith("\"") && component.endsWith("\"")) {
                // Remove quotes and append
                value.append(component.substring(1, component.length() - 1));
            }
        }
        return value.length() > 0 ? value.toString() : null;
    }
    
    /**
     * Generate Z3 constraints for path traversal vulnerabilities
     */
    private String generateZ3PathConstraints() {
        StringBuilder code = new StringBuilder();
        code.append("# Path Construction Constraints\n");
        
        for (StringParameterConstraint constraint : _stringConstraints) {
            String variableName = _parameterVariableMap.get(constraint);
            StringParameterConstraint.PathType pathType = constraint.getPathType();
            
            if (pathType == StringParameterConstraint.PathType.PARTIALLY_CONTROLLED) {
                code.append("# Path partially controlled by external input\n");
                code.append("# Base: ").append(constraint.getHardCodedPrefix()).append("\n");
                
                // Document external input sources
                for (StringParameterConstraint.ExternalInputSource source : constraint.getExternalInputSources()) {
                    code.append("# External input: ").append(formatSourceDescription(source)).append("\n");
                }
                
                code.append("\n");
                
                // Generate constraint for the path
                code.append(variableName).append(" = String('").append(variableName).append("')\n");
                
                if (constraint.getHardCodedPrefix() != null && !constraint.getHardCodedPrefix().isEmpty()) {
                    // Add prefix constraint
                    code.append("s.add(").append(variableName)
                        .append(".startswith(\"").append(constraint.getHardCodedPrefix()).append("\"))\n");
                }
                
            } else if (pathType == StringParameterConstraint.PathType.FULLY_CONTROLLED) {
                code.append("# Path fully controlled by external input\n");
                
                // Document external input sources with enhanced information
                for (StringParameterConstraint.ExternalInputSource source : constraint.getExternalInputSources()) {
                    code.append("# External input source: ").append(formatSourceDescription(source)).append("\n");
                }
                
                code.append("\n");
                
                code.append(variableName).append(" = String('").append(variableName).append("')\n");
                code.append("s.add(").append(variableName).append(" != \"\")\n");
                
                // Add comment showing the source of constraint
                if (!constraint.getExternalInputSources().isEmpty()) {
                    StringParameterConstraint.ExternalInputSource primarySource = constraint.getExternalInputSources().get(0);
                    code.append("# Constraint: path fully controlled by ").append(formatSourceDescription(primarySource)).append("\n");
                }
            }
            
            code.append("\n");
        }
        
        return code.toString();
    }

    /**
     * Generate the complete Z3 constraint code for string parameters (legacy method for compatibility)
     */
    public String getZ3ConstraintCode() {
        return generatePathConstraints();
    }

    /**
     * Format external input source description for better readability
     */
    private String formatSourceDescription(StringParameterConstraint.ExternalInputSource source) {
        if (source.getFullSourceString() != null && !source.getFullSourceString().isEmpty()) {
            return source.getFullSourceString();
        }
        
        StringBuilder desc = new StringBuilder();
        
        // Format based on source type
        switch (source.getSourceType()) {
            case "intent":
                desc.append("intent.").append(source.getSourceMethod());
                if (source.getSourceParameter() != null) {
                    desc.append("(\"").append(source.getSourceParameter()).append("\")");
                } else {
                    desc.append("(?)");
                }
                break;
            case "uri":
                desc.append("uri.").append(source.getSourceMethod()).append("()");
                if (source.getSourceParameter() != null) {
                    desc.append(" [parameter: \"").append(source.getSourceParameter()).append("\"]");
                }
                break;
            case "bundle":
                desc.append("bundle.").append(source.getSourceMethod());
                if (source.getSourceParameter() != null) {
                    desc.append("(\"").append(source.getSourceParameter()).append("\")");
                } else {
                    desc.append("(?)");
                }
                break;
            case "content_values":
                desc.append("contentValues.").append(source.getSourceMethod());
                if (source.getSourceParameter() != null) {
                    desc.append("(\"").append(source.getSourceParameter()).append("\")");
                } else {
                    desc.append("(?)");
                }
                break;
            default:
                return source.toString();
        }
        
        return desc.toString();
    }

    /**
     * Generate Z3 variable declarations for string parameters
     */
    private String generateZ3VariableDeclarations() {
        StringBuilder declarations = new StringBuilder();
        
        for (Map.Entry<StringParameterConstraint, String> entry : _parameterVariableMap.entrySet()) {
            StringParameterConstraint constraint = entry.getKey();
            String variableName = entry.getValue();
            
            // Add comment with parameter information
            declarations.append(String.format("%-20s = String('%-20s')    # %s\n",
                variableName, 
                variableName,
                getParameterDescription(constraint)));
        }
        
        return declarations.toString();
    }

    /**
     * Generate Z3 constraints for string parameters
     */
    private String generateZ3Constraints() {
        List<String> constraintStrings = new ArrayList<>();
        
        for (StringParameterConstraint paramConstraint : _stringConstraints) {
            String variableName = _parameterVariableMap.get(paramConstraint);
            
            // Add constraints from the parameter's constraint predicate
            if (paramConstraint.getConstraints() != null) {
                String constraintStr = convertPredicateToZ3(paramConstraint.getConstraints(), variableName);
                if (!constraintStr.trim().isEmpty()) {
                    constraintStrings.add(constraintStr);
                }
            }
            
            // Add basic constraints based on parameter analysis
            List<String> basicConstraints = generateBasicConstraints(paramConstraint, variableName);
            constraintStrings.addAll(basicConstraints);
        }
        
        if (constraintStrings.isEmpty()) {
            return "";
        }
        
        if (constraintStrings.size() == 1) {
            return constraintStrings.get(0);
        }
        
        return "And(" + String.join(", ", constraintStrings) + ")";
    }

    /**
     * Generate basic constraints for a string parameter
     */
    private List<String> generateBasicConstraints(StringParameterConstraint constraint, String variableName) {
        List<String> constraints = new ArrayList<>();
        
        // Non-null constraint for non-hardcoded parameters
        if (!constraint.isHardCoded()) {
            constraints.add(variableName + " != \"\"");
        }
        
        // Add hard-coded value constraint if parameter is constant
        if (constraint.isHardCoded() && !constraint.getConstructionComponents().isEmpty()) {
            String hardcodedValue = constraint.getConstructionComponents().get(0);
            if (hardcodedValue.startsWith("\"") && hardcodedValue.endsWith("\"")) {
                // Remove quotes for Z3 string literal
                String value = hardcodedValue.substring(1, hardcodedValue.length() - 1);
                constraints.add(variableName + " == \"" + value + "\"");
            }
        }
        
        return constraints;
    }

    /**
     * Convert a Predicate to Z3 constraint string (simplified version)
     */
    private String convertPredicateToZ3(Predicate predicate, String variableName) {
        // For now, return empty string - this would need to be enhanced
        // to properly convert PathSentinel predicates to Z3 string constraints
        return "";
    }

    /**
     * Generate variable mapping for string parameters
     */
    private void generateVariableMap() {
        for (StringParameterConstraint constraint : _stringConstraints) {
            String variableName = "file_path";
            if (_stringConstraints.size() > 1) {
                variableName = "file_path" + (_nextVariableNum++);
            }
            _parameterVariableMap.put(constraint, variableName);
        }
    }

    /**
     * Get a description of the parameter for comment generation
     */
    private String getParameterDescription(StringParameterConstraint constraint) {
        return String.format("Parameter %d of %s: %s", 
            constraint.getParameterIndex(),
            constraint.getTargetMethod().getName(),
            constraint.getConstructionDescription());
    }

    /**
     * Generate JSON metadata about string parameters
     */
    public JsonObject getStringParameterInfoJson() {
        JsonObject infoJson = new JsonObject();
        
        if (_stringConstraints.isEmpty()) {
            return infoJson;
        }
        
        // Add vulnerability type
        StringParameterConstraint firstConstraint = _stringConstraints.get(0);
        StringParameterConstraint.PathType pathType = firstConstraint.getPathType();
        
        String vulnType = "unknown";
        if (pathType == StringParameterConstraint.PathType.HARD_CODED) {
            vulnType = "hijacking";
        } else if (pathType == StringParameterConstraint.PathType.PARTIALLY_CONTROLLED) {
            vulnType = "traversal_partial";
        } else if (pathType == StringParameterConstraint.PathType.FULLY_CONTROLLED) {
            vulnType = "traversal_full";
        }
        
        infoJson.addProperty("vulnerability_type", vulnType);
        infoJson.addProperty("path_type", pathType.toString());
        infoJson.addProperty("targetMethod", firstConstraint.getTargetMethod().getSignature());
        
        // Add path info
        JsonObject pathInfo = new JsonObject();
        pathInfo.addProperty("type", pathType.toString().toLowerCase());
        pathInfo.addProperty("construction", firstConstraint.getConstructionPattern());
        
        if (pathType == StringParameterConstraint.PathType.HARD_CODED) {
            pathInfo.addProperty("exact_path", firstConstraint.getHardCodedValue());
        } else if (pathType == StringParameterConstraint.PathType.PARTIALLY_CONTROLLED) {
            pathInfo.addProperty("hard_coded_prefix", firstConstraint.getHardCodedPrefix());
        }
        
        // Add external input sources
        if (!firstConstraint.getExternalInputSources().isEmpty()) {
            JsonArray sources = new JsonArray();
            for (StringParameterConstraint.ExternalInputSource inputSource : firstConstraint.getExternalInputSources()) {
                JsonObject sourceJson = new JsonObject();
                sourceJson.addProperty("source_type", inputSource.getSourceType());
                sourceJson.addProperty("source_method", inputSource.getSourceMethod());
                if (inputSource.getSourceParameter() != null) {
                    sourceJson.addProperty("source_parameter", inputSource.getSourceParameter());
                }
                sourceJson.addProperty("full_source", inputSource.getFullSourceString());
                sources.add(sourceJson);
            }
            pathInfo.add("external_inputs", sources);
        }
        
        infoJson.add("path_info", pathInfo);
        
        // Add parameters detail
        JsonObject parametersJson = new JsonObject();
        for (Map.Entry<StringParameterConstraint, String> entry : _parameterVariableMap.entrySet()) {
            StringParameterConstraint constraint = entry.getKey();
            String variableName = entry.getValue();
            
            JsonObject paramInfo = new JsonObject();
            paramInfo.addProperty("parameterIndex", constraint.getParameterIndex());
            paramInfo.addProperty("parameterName", constraint.getParameterName());
            paramInfo.addProperty("construction", constraint.getConstructionDescription());
            paramInfo.addProperty("isHardCoded", constraint.isHardCoded());
            paramInfo.addProperty("hasExternalInput", constraint.hasExternalInput());
            paramInfo.addProperty("z3Variable", variableName);
            
            parametersJson.add("param" + constraint.getParameterIndex(), paramInfo);
        }
        
        infoJson.add("parameters", parametersJson);
        
        return infoJson;
    }

    /**
     * Get mapping of string parameter constraints to Z3 variable names
     */
    public Map<StringParameterConstraint, String> getParameterVariableMap() {
        return new HashMap<>(_parameterVariableMap);
    }
    
    /**
     * Check if a path appears to be a complete resolved path (contains directory separators)
     */
    private boolean isCompleteResolvedPath(String path) {
        return path != null && 
               (path.contains("/") || path.contains("\\")) &&
               !path.equals("provider_files") && // Not just a filename
               path.length() > 10; // Reasonably long path
    }
}