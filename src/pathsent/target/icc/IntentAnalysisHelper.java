package pathsent.target.icc;

import java.util.*;
import java.net.URI;
import java.net.URISyntaxException;
import soot.*;
import soot.jimple.*;
import soot.toolkits.graph.UnitGraph;

/**
 * Helper class for analyzing Intent objects and their properties
 * Inspired by Amandroid's IntentHelper for precise Intent content extraction
 */
public class IntentAnalysisHelper {
    
    /**
     * Represents an Intent with its extracted properties
     */
    public static class IntentContent {
        private boolean explicit = false;
        private boolean precise = true;
        private Set<String> componentNames = new HashSet<>();
        private Set<String> actions = new HashSet<>();
        private Set<String> categories = new HashSet<>();
        private Set<UriData> uriData = new HashSet<>();
        private Set<String> mimeTypes = new HashSet<>();
        
        // Getters and setters
        public boolean isExplicit() { return explicit; }
        public void setExplicit(boolean explicit) { this.explicit = explicit; }
        
        public boolean isPrecise() { return precise; }
        public void setPrecise(boolean precise) { this.precise = precise; }
        
        public Set<String> getComponentNames() { return componentNames; }
        public Set<String> getActions() { return actions; }
        public Set<String> getCategories() { return categories; }
        public Set<UriData> getUriData() { return uriData; }
        public Set<String> getMimeTypes() { return mimeTypes; }
        
        public void addComponentName(String name) { componentNames.add(name); }
        public void addAction(String action) { actions.add(action); }
        public void addCategory(String category) { categories.add(category); }
        public void addUriData(UriData uri) { uriData.add(uri); }
        public void addMimeType(String type) { mimeTypes.add(type); }
        
        @Override
        public String toString() {
            return String.format("IntentContent{explicit=%s, precise=%s, components=%s, actions=%s, categories=%s}",
                explicit, precise, componentNames, actions, categories);
        }
    }
    
    /**
     * Represents URI data extracted from Intent
     */
    public static class UriData {
        private String scheme;
        private String host;
        private String port;
        private String path;
        
        public UriData() {}
        
        public UriData(String scheme, String host, String port, String path) {
            this.scheme = scheme;
            this.host = host;
            this.port = port;
            this.path = path;
        }
        
        // Getters and setters
        public String getScheme() { return scheme; }
        public void setScheme(String scheme) { this.scheme = scheme; }
        
        public String getHost() { return host; }
        public void setHost(String host) { this.host = host; }
        
        public String getPort() { return port; }
        public void setPort(String port) { this.port = port; }
        
        public String getPath() { return path; }
        public void setPath(String path) { this.path = path; }
        
        public void set(String scheme, String host, String port, String path) {
            this.scheme = scheme;
            this.host = host;
            this.port = port;
            this.path = path;
        }
        
        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (obj == null || getClass() != obj.getClass()) return false;
            UriData uriData = (UriData) obj;
            return Objects.equals(scheme, uriData.scheme) &&
                   Objects.equals(host, uriData.host) &&
                   Objects.equals(port, uriData.port) &&
                   Objects.equals(path, uriData.path);
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(scheme, host, port, path);
        }
        
        @Override
        public String toString() {
            return String.format("UriData{scheme='%s', host='%s', port='%s', path='%s'}", 
                scheme, host, port, path);
        }
    }
    
    /**
     * Extract Intent content from Intent construction and modification statements
     */
    public static Set<IntentContent> extractIntentContents(Value intentValue, Body body) {
        Set<IntentContent> contents = new HashSet<>();
        IntentContent content = new IntentContent();
        
        // Analyze the body for Intent field assignments
        for (Unit unit : body.getUnits()) {
            if (unit instanceof AssignStmt) {
                AssignStmt assign = (AssignStmt) unit;
                
                // Check if this assignment modifies the Intent
                if (isIntentFieldAssignment(assign, intentValue)) {
                    analyzeIntentFieldAssignment(assign, content);
                }
            } else if (unit instanceof InvokeStmt) {
                InvokeStmt invoke = (InvokeStmt) unit;
                
                // Check if this is an Intent method call
                if (isIntentMethodCall(invoke, intentValue)) {
                    analyzeIntentMethodCall(invoke, content);
                }
            }
        }
        
        contents.add(content);
        return contents;
    }
    
    /**
     * Check if an assignment statement modifies an Intent field
     */
    private static boolean isIntentFieldAssignment(AssignStmt assign, Value intentValue) {
        Value leftOp = assign.getLeftOp();
        
        if (leftOp instanceof InstanceFieldRef) {
            InstanceFieldRef fieldRef = (InstanceFieldRef) leftOp;
            return fieldRef.getBase().equals(intentValue);
        }
        
        return false;
    }
    
    /**
     * Analyze Intent field assignment
     */
    private static void analyzeIntentFieldAssignment(AssignStmt assign, IntentContent content) {
        InstanceFieldRef fieldRef = (InstanceFieldRef) assign.getLeftOp();
        String fieldName = fieldRef.getField().getName();
        Value rightOp = assign.getRightOp();
        
        switch (fieldName) {
            case "mComponent":
                content.setExplicit(true);
                if (rightOp instanceof StringConstant) {
                    content.addComponentName(((StringConstant) rightOp).value);
                } else {
                    content.setPrecise(false);
                }
                break;
            case "mAction":
                if (rightOp instanceof StringConstant) {
                    content.addAction(((StringConstant) rightOp).value);
                } else {
                    content.setPrecise(false);
                }
                break;
            case "mType":
                if (rightOp instanceof StringConstant) {
                    content.addMimeType(((StringConstant) rightOp).value);
                } else {
                    content.setPrecise(false);
                }
                break;
        }
    }
    
    /**
     * Check if an invoke statement is an Intent method call
     */
    private static boolean isIntentMethodCall(InvokeStmt invoke, Value intentValue) {
        InvokeExpr expr = invoke.getInvokeExpr();
        
        if (expr instanceof InstanceInvokeExpr) {
            InstanceInvokeExpr instanceInvoke = (InstanceInvokeExpr) expr;
            return instanceInvoke.getBase().equals(intentValue);
        }
        
        return false;
    }
    
    /**
     * Analyze Intent method call
     */
    private static void analyzeIntentMethodCall(InvokeStmt invoke, IntentContent content) {
        InvokeExpr expr = invoke.getInvokeExpr();
        String methodName = expr.getMethod().getName();
        
        switch (methodName) {
            case "setComponent":
                content.setExplicit(true);
                if (expr.getArgCount() > 0 && expr.getArg(0) instanceof StringConstant) {
                    content.addComponentName(((StringConstant) expr.getArg(0)).value);
                } else {
                    content.setPrecise(false);
                }
                break;
            case "setAction":
                if (expr.getArgCount() > 0 && expr.getArg(0) instanceof StringConstant) {
                    content.addAction(((StringConstant) expr.getArg(0)).value);
                } else {
                    content.setPrecise(false);
                }
                break;
            case "addCategory":
                if (expr.getArgCount() > 0 && expr.getArg(0) instanceof StringConstant) {
                    content.addCategory(((StringConstant) expr.getArg(0)).value);
                } else {
                    content.setPrecise(false);
                }
                break;
            case "setData":
            case "setDataAndType":
                if (expr.getArgCount() > 0 && expr.getArg(0) instanceof StringConstant) {
                    String uriString = ((StringConstant) expr.getArg(0)).value;
                    UriData uri = parseUriString(uriString);
                    if (uri != null) {
                        content.addUriData(uri);
                    }
                } else {
                    content.setPrecise(false);
                }
                break;
            case "setType":
                if (expr.getArgCount() > 0 && expr.getArg(0) instanceof StringConstant) {
                    content.addMimeType(((StringConstant) expr.getArg(0)).value);
                } else {
                    content.setPrecise(false);
                }
                break;
        }
    }
    
    /**
     * Parse URI string to extract components
     */
    private static UriData parseUriString(String uriString) {
        if (uriString == null || uriString.isEmpty()) {
            return null;
        }
        
        try {
            // Handle special cases like tel: and file:
            if (uriString.startsWith("tel:") || uriString.startsWith("file:")) {
                if (uriString.contains(":")) {
                    String scheme = uriString.substring(0, uriString.indexOf(":"));
                    UriData uri = new UriData();
                    uri.setScheme(scheme);
                    return uri;
                }
                return null;
            }
            
            // Handle normal URIs
            if (uriString.contains("://") && uriString.indexOf("://") < uriString.length()) {
                URI uri = new URI(uriString);
                return new UriData(
                    uri.getScheme(),
                    uri.getHost(),
                    uri.getPort() != -1 ? String.valueOf(uri.getPort()) : null,
                    uri.getPath() != null && !uri.getPath().isEmpty() ? uri.getPath() : null
                );
            } else if (uriString.contains(":")) {
                // Simple scheme-only URI
                String scheme = uriString.substring(0, uriString.indexOf(":"));
                UriData uri = new UriData();
                uri.setScheme(scheme);
                return uri;
            }
        } catch (URISyntaxException e) {
            // Invalid URI, return null
        }
        
        return null;
    }
}