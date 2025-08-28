package pathsent.target.icc;

import pathsent.target.ManifestAnalysis;
import pathsent.target.callgraph.AndroidCallGraphPatching;
import pathsent.target.callgraph.BroadcastReceiverPatcher;
import pathsent.target.callgraph.MessengerPatcher;

import soot.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Multi-component analysis for linking ICC communications across Android components
 * Based on Amandroid's component-based analysis architecture
 */
public class MultiComponentAnalysis {
    private final ManifestAnalysis manifestAnalysis;
    private final CallGraph callGraph;
    
    // Component summaries from different patchers
    private final Map<SootClass, ComponentSummaryTable> allComponentSummaries;
    
    // ICC communication links discovered
    private final Set<ICCLink> iccLinks;
    
    // Static field communication links
    private final Set<StaticFieldLink> staticFieldLinks;
    
    // ICC call graph enhancer for explicit ICC edges
    private IccCallGraphEnhancer iccCallGraphEnhancer;
    
    public MultiComponentAnalysis(ManifestAnalysis manifestAnalysis, CallGraph callGraph) {
        this.manifestAnalysis = manifestAnalysis;
        this.callGraph = callGraph;
        this.allComponentSummaries = new HashMap<>();
        this.iccLinks = new HashSet<>();
        this.staticFieldLinks = new HashSet<>();
    }
    
    /**
     * Perform multi-component analysis linking
     */
    public void performAnalysis(AndroidCallGraphPatching patching) {
        System.err.println("PATHSENT-MULTICOMPONENT: Starting multi-component analysis");
        
        // Phase 1: Enhance call graph with explicit ICC edges (IccTA-style)
        enhanceCallGraphWithIccEdges();
        
        // Phase 2: Collect component summaries from all patchers (Amandroid-style)
        collectComponentSummaries(patching);
        
        // Phase 3: Link ICC communications using both approaches
        linkICCCommunications();
        
        // Phase 4: Link RPC communications  
        linkRPCCommunications();
        
        // Phase 5: Link static field communications
        linkStaticFieldCommunications();
        
        // Phase 6: Integrate ICC enhancer results
        integrateIccEnhancerResults();
        
        // Phase 7: Generate summary report
        generateAnalysisReport();
        
        System.err.println("PATHSENT-MULTICOMPONENT: Multi-component analysis completed");
    }
    
    /**
     * Enhance call graph with explicit ICC edges using IccTA-style approach
     */
    private void enhanceCallGraphWithIccEdges() {
        System.err.println("PATHSENT-MULTICOMPONENT: Enhancing call graph with ICC edges");
        
        try {
            iccCallGraphEnhancer = new IccCallGraphEnhancer(manifestAnalysis, callGraph);
            iccCallGraphEnhancer.enhanceCallGraph();
            
            System.err.println("PATHSENT-MULTICOMPONENT: ICC call graph enhancement completed");
        } catch (Exception e) {
            System.err.println("PATHSENT-MULTICOMPONENT: Failed to enhance call graph with ICC edges: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Integrate results from IccCallGraphEnhancer with component summaries
     */
    private void integrateIccEnhancerResults() {
        System.err.println("PATHSENT-MULTICOMPONENT: Integrating ICC enhancer results");
        
        if (iccCallGraphEnhancer == null) {
            System.err.println("PATHSENT-MULTICOMPONENT: No ICC enhancer results to integrate");
            return;
        }
        
        int integratedCount = 0;
        
        // Convert IccCommunications to ICCLinks
        for (IccCallGraphEnhancer.IccCommunication comm : iccCallGraphEnhancer.getIccCommunications()) {
            if (comm.getTargetMethod() != null) {
                // Create ICCCallerInfo and ICCCalleeInfo from the communication
                ConcreteICCCallerInfo caller = new ConcreteICCCallerInfo(
                    comm.getSourceMethod().getDeclaringClass(), 
                    comm.getSourceMethod(), 
                    comm.getIccUnit(),
                    comm.getTargetAction());
                ConcreteICCCalleeInfo callee = new ConcreteICCCalleeInfo(
                    comm.getTargetMethod().getDeclaringClass(), 
                    comm.getTargetMethod(),
                    comm.getTargetAction());
                
                ICCLink.Type linkType = convertCommTypeToLinkType(comm.getType());
                ICCLink link = new ICCLink(caller, callee, linkType);
                
                iccLinks.add(link);
                integratedCount++;
                
                System.err.println("PATHSENT-MULTICOMPONENT: Integrated ICC link: " + 
                                  comm.getSourceMethod().getDeclaringClass().getName() + " -> " + 
                                  comm.getTargetMethod().getDeclaringClass().getName() + 
                                  " (" + comm.getType() + ")");
            }
        }
        
        System.err.println("PATHSENT-MULTICOMPONENT: Integrated " + integratedCount + " ICC enhancer results");
    }
    
    /**
     * Convert IccCommunication.Type to ICCLink.Type
     */
    private ICCLink.Type convertCommTypeToLinkType(IccCallGraphEnhancer.IccCommunication.Type commType) {
        switch (commType) {
            case START_ACTIVITY:
            case START_SERVICE:
            case SEND_BROADCAST:
            case CONTENT_PROVIDER:
            case REGISTER_RECEIVER:
                return ICCLink.Type.INTENT;
            case MESSENGER:
                return ICCLink.Type.RPC;
            default:
                return ICCLink.Type.INTENT;
        }
    }
    
    /**
     * Collect component summaries from all patchers
     */
    private void collectComponentSummaries(AndroidCallGraphPatching patching) {
        System.err.println("PATHSENT-MULTICOMPONENT: Collecting component summaries");
        
        // Get summaries from BroadcastReceiverPatcher
        // Note: In real implementation, we would need access to patcher instances
        // For now, this is a placeholder showing the intended architecture
        
        int summaryCount = 0;
        for (SootClass clazz : Scene.v().getApplicationClasses()) {
            if (isAndroidComponent(clazz)) {
                ComponentSummaryTable summary = new ComponentSummaryTable(clazz);
                allComponentSummaries.put(clazz, summary);
                summaryCount++;
            }
        }
        
        System.err.println("PATHSENT-MULTICOMPONENT: Collected " + summaryCount + " component summaries");
    }
    
    /**
     * Link ICC (Intent-based) communications
     */
    private void linkICCCommunications() {
        System.err.println("PATHSENT-MULTICOMPONENT: Linking ICC communications");
        
        // Get all ICC callers and callees
        Set<ICCCallerInfo> allCallers = new HashSet<>();
        Set<ICCCalleeInfo> allCallees = new HashSet<>();
        
        for (ComponentSummaryTable summary : allComponentSummaries.values()) {
            ComponentSummaryTable.ICCSummary iccSummary = summary.getSummary(ComponentSummaryTable.Channel.ICC);
            
            for (ComponentSummaryTable.CallerInfo caller : iccSummary.getCallers()) {
                if (caller instanceof ICCCallerInfo) {
                    allCallers.add((ICCCallerInfo) caller);
                }
            }
            
            for (ComponentSummaryTable.CalleeInfo callee : iccSummary.getCallees()) {
                if (callee instanceof ICCCalleeInfo) {
                    allCallees.add((ICCCalleeInfo) callee);
                }
            }
        }
        
        // Match callers with callees
        int linkCount = 0;
        for (ICCCallerInfo caller : allCallers) {
            for (ICCCalleeInfo callee : allCallees) {
                if (callee.matchesCaller(caller)) {
                    ICCLink link = new ICCLink(caller, callee, ICCLink.Type.INTENT);
                    iccLinks.add(link);
                    linkCount++;
                    
                    System.err.println("PATHSENT-MULTICOMPONENT: ICC Link: " + 
                        caller.getComponent().getName() + " -> " + callee.getComponent().getName());
                }
            }
        }
        
        System.err.println("PATHSENT-MULTICOMPONENT: Created " + linkCount + " ICC links");
    }
    
    /**
     * Link RPC (Remote Procedure Call) communications
     */
    private void linkRPCCommunications() {
        System.err.println("PATHSENT-MULTICOMPONENT: Linking RPC communications");
        
        // Similar to ICC linking but for RPC communications
        Set<ICCCallerInfo> rpcCallers = new HashSet<>();
        Set<ICCCalleeInfo> rpcCallees = new HashSet<>();
        
        for (ComponentSummaryTable summary : allComponentSummaries.values()) {
            ComponentSummaryTable.RPCSummary rpcSummary = summary.getSummary(ComponentSummaryTable.Channel.RPC);
            
            for (ComponentSummaryTable.CallerInfo caller : rpcSummary.getCallers()) {
                if (caller instanceof ICCCallerInfo) {
                    rpcCallers.add((ICCCallerInfo) caller);
                }
            }
            
            for (ComponentSummaryTable.CalleeInfo callee : rpcSummary.getCallees()) {
                if (callee instanceof ICCCalleeInfo) {
                    rpcCallees.add((ICCCalleeInfo) callee);
                }
            }
        }
        
        // Match RPC callers with callees
        int rpcLinkCount = 0;
        for (ICCCallerInfo caller : rpcCallers) {
            for (ICCCalleeInfo callee : rpcCallees) {
                if (callee.matchesCaller(caller)) {
                    ICCLink link = new ICCLink(caller, callee, ICCLink.Type.RPC);
                    iccLinks.add(link);
                    rpcLinkCount++;
                    
                    System.err.println("PATHSENT-MULTICOMPONENT: RPC Link: " + 
                        caller.getComponent().getName() + " -> " + callee.getComponent().getName());
                }
            }
        }
        
        System.err.println("PATHSENT-MULTICOMPONENT: Created " + rpcLinkCount + " RPC links");
    }
    
    /**
     * Link static field communications
     */
    private void linkStaticFieldCommunications() {
        System.err.println("PATHSENT-MULTICOMPONENT: Linking static field communications");
        
        // Track static field reads and writes across components
        Map<String, Set<SootClass>> fieldWriters = new HashMap<>();
        Map<String, Set<SootClass>> fieldReaders = new HashMap<>();
        
        for (ComponentSummaryTable summary : allComponentSummaries.values()) {
            ComponentSummaryTable.StaticFieldSummary sfSummary = 
                    summary.getSummary(ComponentSummaryTable.Channel.STATIC_FIELD);
            
            for (ComponentSummaryTable.CallerInfo caller : sfSummary.getCallers()) {
                // Static field writers
                String fieldName = extractStaticFieldName(caller);
                if (fieldName != null) {
                    fieldWriters.computeIfAbsent(fieldName, k -> new HashSet<>())
                               .add(caller.getComponent());
                }
            }
            
            for (ComponentSummaryTable.CalleeInfo callee : sfSummary.getCallees()) {
                // Static field readers
                String fieldName = extractStaticFieldName(callee);
                if (fieldName != null) {
                    fieldReaders.computeIfAbsent(fieldName, k -> new HashSet<>())
                               .add(callee.getComponent());
                }
            }
        }
        
        // Create static field links between writers and readers
        int sfLinkCount = 0;
        for (String fieldName : fieldWriters.keySet()) {
            Set<SootClass> writers = fieldWriters.get(fieldName);
            Set<SootClass> readers = fieldReaders.getOrDefault(fieldName, Collections.emptySet());
            
            for (SootClass writer : writers) {
                for (SootClass reader : readers) {
                    if (!writer.equals(reader)) {
                        StaticFieldLink link = new StaticFieldLink(writer, reader, fieldName);
                        staticFieldLinks.add(link);
                        sfLinkCount++;
                        
                        System.err.println("PATHSENT-MULTICOMPONENT: Static field link: " + 
                            writer.getName() + " -> " + reader.getName() + " (" + fieldName + ")");
                    }
                }
            }
        }
        
        System.err.println("PATHSENT-MULTICOMPONENT: Created " + sfLinkCount + " static field links");
    }
    
    /**
     * Generate analysis report
     */
    private void generateAnalysisReport() {
        System.err.println("\n=== PATHSENT MULTI-COMPONENT ANALYSIS REPORT ===");
        System.err.println("Components analyzed: " + allComponentSummaries.size());
        System.err.println("ICC links: " + iccLinks.size());
        System.err.println("Static field links: " + staticFieldLinks.size());
        
        // Group ICC links by type
        Map<ICCLink.Type, Long> linksByType = iccLinks.stream()
                .collect(Collectors.groupingBy(ICCLink::getType, Collectors.counting()));
        
        System.err.println("\nICC Links by type:");
        for (Map.Entry<ICCLink.Type, Long> entry : linksByType.entrySet()) {
            System.err.println("  " + entry.getKey() + ": " + entry.getValue());
        }
        
        System.err.println("\nComponent Types:");
        Map<String, Long> componentTypes = allComponentSummaries.keySet().stream()
                .collect(Collectors.groupingBy(this::getComponentType, Collectors.counting()));
        
        for (Map.Entry<String, Long> entry : componentTypes.entrySet()) {
            System.err.println("  " + entry.getKey() + ": " + entry.getValue());
        }
        
        System.err.println("===============================================\n");
    }
    
    /**
     * Check if a class is an Android component
     */
    private boolean isAndroidComponent(SootClass clazz) {
        try {
            SootClass activityClass = Scene.v().getSootClass("android.app.Activity");
            SootClass serviceClass = Scene.v().getSootClass("android.app.Service");
            SootClass receiverClass = Scene.v().getSootClass("android.content.BroadcastReceiver");
            SootClass providerClass = Scene.v().getSootClass("android.content.ContentProvider");
            
            return Scene.v().getOrMakeFastHierarchy().isSubclass(clazz, activityClass) ||
                   Scene.v().getOrMakeFastHierarchy().isSubclass(clazz, serviceClass) ||
                   Scene.v().getOrMakeFastHierarchy().isSubclass(clazz, receiverClass) ||
                   Scene.v().getOrMakeFastHierarchy().isSubclass(clazz, providerClass);
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Get component type string
     */
    private String getComponentType(SootClass clazz) {
        try {
            if (Scene.v().getOrMakeFastHierarchy().isSubclass(clazz, Scene.v().getSootClass("android.app.Activity"))) {
                return "Activity";
            } else if (Scene.v().getOrMakeFastHierarchy().isSubclass(clazz, Scene.v().getSootClass("android.app.Service"))) {
                return "Service";
            } else if (Scene.v().getOrMakeFastHierarchy().isSubclass(clazz, Scene.v().getSootClass("android.content.BroadcastReceiver"))) {
                return "BroadcastReceiver";
            } else if (Scene.v().getOrMakeFastHierarchy().isSubclass(clazz, Scene.v().getSootClass("android.content.ContentProvider"))) {
                return "ContentProvider";
            }
        } catch (Exception e) {
            // Ignore
        }
        return "Unknown";
    }
    
    /**
     * Extract static field name from caller/callee info
     */
    private String extractStaticFieldName(Object info) {
        // Placeholder implementation
        // In real implementation, this would extract the field name from the caller/callee
        return info.toString(); // Simplified
    }
    
    /**
     * Get all discovered ICC links
     */
    public Set<ICCLink> getICCLinks() {
        return Collections.unmodifiableSet(iccLinks);
    }
    
    /**
     * Get all discovered static field links
     */
    public Set<StaticFieldLink> getStaticFieldLinks() {
        return Collections.unmodifiableSet(staticFieldLinks);
    }
    
    /**
     * Get component summaries
     */
    public Map<SootClass, ComponentSummaryTable> getComponentSummaries() {
        return Collections.unmodifiableMap(allComponentSummaries);
    }
    
    /**
     * Represents a link between ICC caller and callee
     */
    public static class ICCLink {
        public enum Type {
            INTENT, RPC, MESSENGER
        }
        
        private final ICCCallerInfo caller;
        private final ICCCalleeInfo callee;
        private final Type type;
        
        public ICCLink(ICCCallerInfo caller, ICCCalleeInfo callee, Type type) {
            this.caller = caller;
            this.callee = callee;
            this.type = type;
        }
        
        public ICCCallerInfo getCaller() { return caller; }
        public ICCCalleeInfo getCallee() { return callee; }
        public Type getType() { return type; }
        
        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (obj == null || getClass() != obj.getClass()) return false;
            ICCLink iccLink = (ICCLink) obj;
            return Objects.equals(caller, iccLink.caller) &&
                   Objects.equals(callee, iccLink.callee) &&
                   type == iccLink.type;
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(caller, callee, type);
        }
        
        @Override
        public String toString() {
            return String.format("ICCLink{%s: %s -> %s}", type, caller.getComponent().getName(), callee.getComponent().getName());
        }
    }
    
    /**
     * Represents a static field communication link
     */
    public static class StaticFieldLink {
        private final SootClass writer;
        private final SootClass reader;
        private final String fieldName;
        
        public StaticFieldLink(SootClass writer, SootClass reader, String fieldName) {
            this.writer = writer;
            this.reader = reader;
            this.fieldName = fieldName;
        }
        
        public SootClass getWriter() { return writer; }
        public SootClass getReader() { return reader; }
        public String getFieldName() { return fieldName; }
        
        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (obj == null || getClass() != obj.getClass()) return false;
            StaticFieldLink that = (StaticFieldLink) obj;
            return Objects.equals(writer, that.writer) &&
                   Objects.equals(reader, that.reader) &&
                   Objects.equals(fieldName, that.fieldName);
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(writer, reader, fieldName);
        }
        
        @Override
        public String toString() {
            return String.format("StaticFieldLink{%s -> %s (%s)}", writer.getName(), reader.getName(), fieldName);
        }
    }
    
    /**
     * Concrete implementation of ICCCallerInfo for multi-component analysis
     */
    private static class ConcreteICCCallerInfo extends ICCCallerInfo {
        private final String targetAction;
        
        public ConcreteICCCallerInfo(SootClass component, SootMethod method, Unit callSite, String targetAction) {
            super(component, method, callSite);
            this.targetAction = targetAction;
        }
        
        @Override
        public String getCallerType() {
            return "ICC_CALLER";
        }
        
        public String getTargetAction() {
            return targetAction;
        }
        
        @Override
        public String toString() {
            return String.format("ConcreteICCCallerInfo{%s.%s -> %s}", 
                               component.getName(), method.getName(), targetAction);
        }
    }
    
    /**
     * Concrete implementation of ICCCalleeInfo for multi-component analysis
     */
    private static class ConcreteICCCalleeInfo extends ICCCalleeInfo {
        private final String expectedAction;
        private final SootMethod method;
        
        public ConcreteICCCalleeInfo(SootClass component, SootMethod method, String expectedAction) {
            super(component, true, new HashSet<>());  // exported=true, no permissions for simplicity
            this.method = method;
            this.expectedAction = expectedAction;
        }
        
        @Override
        public String getCalleeType() {
            return "ICC_CALLEE";
        }
        
        @Override
        public boolean matchesCaller(ComponentSummaryTable.CallerInfo caller) {
            if (caller instanceof ConcreteICCCallerInfo) {
                ConcreteICCCallerInfo concreteCaller = (ConcreteICCCallerInfo) caller;
                return expectedAction != null && expectedAction.equals(concreteCaller.getTargetAction());
            }
            return false;
        }
        
        public String getExpectedAction() {
            return expectedAction;
        }
        
        public SootMethod getMethod() {
            return method;
        }
        
        @Override
        public String toString() {
            return String.format("ConcreteICCCalleeInfo{%s.%s <- %s}", 
                               component.getName(), method.getName(), expectedAction);
        }
    }
}