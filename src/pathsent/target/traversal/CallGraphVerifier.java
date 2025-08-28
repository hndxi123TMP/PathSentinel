package pathsent.target.traversal;

import pathsent.target.entrypoint.IEntryPointAnalysis;
import pathsent.target.icc.IccCallGraphEnhancer;
import soot.*;
import soot.jimple.toolkits.callgraph.*;

import java.util.*;

/**
 * CallGraphVerifier validates call graph structure and entry point connectivity.
 * 
 * This class helps diagnose issues with:
 * - Entry point reachability
 * - ICC edge connectivity
 * - Call graph completeness
 * - Orphaned nodes
 */
public class CallGraphVerifier {
    private final CallGraph _callGraph;
    private final IEntryPointAnalysis _entryPointAnalysis;
    private final IccCallGraphEnhancer _iccEnhancer;
    
    public CallGraphVerifier(CallGraph callGraph, IEntryPointAnalysis entryPointAnalysis, 
                           IccCallGraphEnhancer iccEnhancer) {
        _callGraph = callGraph;
        _entryPointAnalysis = entryPointAnalysis;
        _iccEnhancer = iccEnhancer;
    }
    
    /**
     * Perform comprehensive call graph verification
     */
    public void verifyCallGraph() {
        System.err.println("CALL-GRAPH-VERIFIER: ========== Starting Call Graph Verification ==========");
        
        // Basic call graph statistics
        printCallGraphStatistics();
        
        // Verify entry point connectivity
        verifyEntryPointConnectivity();
        
        // Verify ICC edges if available
        if (_iccEnhancer != null) {
            verifyIccConnectivity();
        } else {
            System.err.println("CALL-GRAPH-VERIFIER: ICC Enhancer not available - using PathSentinel native ICC");
            verifyNativeIccConnectivity();
        }
        
        // Check for orphaned nodes
        checkOrphanedNodes();
        
        // Analyze application vs framework connectivity
        analyzeApplicationFrameworkConnectivity();
        
        System.err.println("CALL-GRAPH-VERIFIER: ========== Verification Complete ==========");
    }
    
    /**
     * Print basic call graph statistics
     */
    private void printCallGraphStatistics() {
        System.err.println("CALL-GRAPH-VERIFIER: === Call Graph Statistics ===");
        
        int totalEdges = 0;
        int totalNodes = 0;
        int applicationNodes = 0;
        int frameworkNodes = 0;
        
        Set<MethodOrMethodContext> allNodes = new HashSet<>();
        
        // Count edges and collect nodes
        Iterator<Edge> allEdges = _callGraph.iterator();
        while (allEdges.hasNext()) {
            Edge edge = allEdges.next();
            totalEdges++;
            allNodes.add(edge.getSrc());
            allNodes.add(edge.getTgt());
        }
        
        // Categorize nodes
        for (MethodOrMethodContext node : allNodes) {
            totalNodes++;
            SootClass nodeClass = node.method().getDeclaringClass();
            if (nodeClass.isApplicationClass()) {
                applicationNodes++;
            } else {
                frameworkNodes++;
            }
        }
        
        System.err.println("CALL-GRAPH-VERIFIER: Total edges: " + totalEdges);
        System.err.println("CALL-GRAPH-VERIFIER: Total nodes: " + totalNodes);
        System.err.println("CALL-GRAPH-VERIFIER: Application nodes: " + applicationNodes);
        System.err.println("CALL-GRAPH-VERIFIER: Framework nodes: " + frameworkNodes);
        System.err.println("CALL-GRAPH-VERIFIER: Application ratio: " + 
                          (totalNodes > 0 ? String.format("%.1f%%", (applicationNodes * 100.0 / totalNodes)) : "0%"));
    }
    
    /**
     * Verify that entry points are properly connected in the call graph
     */
    private void verifyEntryPointConnectivity() {
        System.err.println("CALL-GRAPH-VERIFIER: === Entry Point Connectivity Analysis ===");
        
        Set<MethodOrMethodContext> entryPoints = _entryPointAnalysis.getEntryPoints();
        System.err.println("CALL-GRAPH-VERIFIER: Total entry points: " + entryPoints.size());
        
        int connectedEntryPoints = 0;
        int entryPointsWithOutgoingEdges = 0;
        int entryPointsWithIncomingEdges = 0;
        
        for (MethodOrMethodContext entryPoint : entryPoints) {
            boolean hasOutgoing = _callGraph.edgesOutOf(entryPoint).hasNext();
            boolean hasIncoming = _callGraph.edgesInto(entryPoint).hasNext();
            
            if (hasOutgoing || hasIncoming) {
                connectedEntryPoints++;
            }
            
            if (hasOutgoing) {
                entryPointsWithOutgoingEdges++;
                System.err.println("CALL-GRAPH-VERIFIER: Entry point with outgoing edges: " + 
                                  entryPoint.method().getSignature() + 
                                  " (" + countEdges(_callGraph.edgesOutOf(entryPoint)) + " edges)");
            }
            
            if (hasIncoming) {
                entryPointsWithIncomingEdges++;
                System.err.println("CALL-GRAPH-VERIFIER: Entry point with incoming edges: " + 
                                  entryPoint.method().getSignature() + 
                                  " (" + countEdges(_callGraph.edgesInto(entryPoint)) + " edges)");
            }
            
            if (!hasOutgoing && !hasIncoming) {
                System.err.println("CALL-GRAPH-VERIFIER: WARNING - Isolated entry point: " + 
                                  entryPoint.method().getSignature());
            }
        }
        
        System.err.println("CALL-GRAPH-VERIFIER: Connected entry points: " + connectedEntryPoints + 
                          "/" + entryPoints.size());
        System.err.println("CALL-GRAPH-VERIFIER: Entry points with outgoing edges: " + entryPointsWithOutgoingEdges);
        System.err.println("CALL-GRAPH-VERIFIER: Entry points with incoming edges: " + entryPointsWithIncomingEdges);
        
        if (connectedEntryPoints == 0) {
            System.err.println("CALL-GRAPH-VERIFIER: CRITICAL - No connected entry points found! " +
                              "Path finding will fail.");
        }
    }
    
    /**
     * Verify ICC edge connectivity
     */
    private void verifyIccConnectivity() {
        System.err.println("CALL-GRAPH-VERIFIER: === ICC Connectivity Analysis ===");
        
        _iccEnhancer.verifyIccEdges(); // Use existing verification method
        
        // Additional ICC-specific checks
        Set<IccCallGraphEnhancer.IccCommunication> iccCommunications = _iccEnhancer.getIccCommunications();
        
        int totalIccCommunications = iccCommunications.size();
        int iccWithTargetMethods = 0;
        int verifiableIccEdges = 0;
        
        for (IccCallGraphEnhancer.IccCommunication comm : iccCommunications) {
            if (comm.getTargetMethod() != null) {
                iccWithTargetMethods++;
                
                // Check if we can find the source method in call graph
                MethodOrMethodContext srcContext = findMethodInCallGraph(comm.getSourceMethod());
                MethodOrMethodContext tgtContext = findMethodInCallGraph(comm.getTargetMethod());
                
                if (srcContext != null && tgtContext != null) {
                    verifiableIccEdges++;
                } else {
                    System.err.println("CALL-GRAPH-VERIFIER: ICC edge not verifiable: " + 
                                      comm.getSourceMethod().getSignature() + " -> " + 
                                      comm.getTargetMethod().getSignature() + 
                                      " (src in graph: " + (srcContext != null) + 
                                      ", tgt in graph: " + (tgtContext != null) + ")");
                }
            }
        }
        
        System.err.println("CALL-GRAPH-VERIFIER: Total ICC communications: " + totalIccCommunications);
        System.err.println("CALL-GRAPH-VERIFIER: ICC with target methods: " + iccWithTargetMethods);
        System.err.println("CALL-GRAPH-VERIFIER: Verifiable ICC edges: " + verifiableIccEdges);
    }
    
    /**
     * Verify native ICC connectivity (PathSentinel's built-in ICC handling)
     */
    private void verifyNativeIccConnectivity() {
        System.err.println("CALL-GRAPH-VERIFIER: === Native ICC Connectivity Analysis ===");
        
        // Look for ICC-related edges in the call graph that connect different components
        int interComponentEdges = 0;
        int totalApplicationEdges = 0;
        
        Set<String> sourceComponents = new HashSet<>();
        Set<String> targetComponents = new HashSet<>();
        
        Iterator<Edge> allEdges = _callGraph.iterator();
        while (allEdges.hasNext()) {
            Edge edge = allEdges.next();
            
            SootClass srcClass = edge.getSrc().method().getDeclaringClass();
            SootClass tgtClass = edge.getTgt().method().getDeclaringClass();
            
            // Only consider application classes
            if (!srcClass.isApplicationClass() || !tgtClass.isApplicationClass()) {
                continue;
            }
            
            totalApplicationEdges++;
            sourceComponents.add(srcClass.getName());
            targetComponents.add(tgtClass.getName());
            
            // Check if this could be an ICC edge (between different components)
            if (!srcClass.equals(tgtClass)) {
                // Check if target method is a lifecycle method
                String tgtMethodName = edge.getTgt().method().getName();
                if (isLifecycleMethod(tgtMethodName)) {
                    interComponentEdges++;
                    System.err.println("CALL-GRAPH-VERIFIER: Potential ICC edge: " + 
                                      srcClass.getName() + " -> " + 
                                      tgtClass.getName() + "." + tgtMethodName);
                }
            }
        }
        
        System.err.println("CALL-GRAPH-VERIFIER: Total application edges: " + totalApplicationEdges);
        System.err.println("CALL-GRAPH-VERIFIER: Inter-component edges: " + interComponentEdges);
        System.err.println("CALL-GRAPH-VERIFIER: Source components: " + sourceComponents.size());
        System.err.println("CALL-GRAPH-VERIFIER: Target components: " + targetComponents.size());
        
        // Check connectivity between known Android components
        verifyAndroidComponentConnectivity();
    }
    
    /**
     * Check if method name is a typical Android lifecycle method
     */
    private boolean isLifecycleMethod(String methodName) {
        return methodName.equals("onCreate") || methodName.equals("onStart") || 
               methodName.equals("onResume") || methodName.equals("onPause") ||
               methodName.equals("onStop") || methodName.equals("onDestroy") ||
               methodName.equals("onReceive") || methodName.equals("onStartCommand") ||
               methodName.equals("onBind") || methodName.equals("query") ||
               methodName.equals("insert") || methodName.equals("update") ||
               methodName.equals("delete");
    }
    
    /**
     * Verify connectivity between Android components
     */
    private void verifyAndroidComponentConnectivity() {
        System.err.println("CALL-GRAPH-VERIFIER: === Android Component Connectivity ===");
        
        Set<String> activities = new HashSet<>();
        Set<String> services = new HashSet<>();
        Set<String> receivers = new HashSet<>();
        Set<String> providers = new HashSet<>();
        
        // Categorize application classes by Android component type
        for (SootClass clazz : Scene.v().getApplicationClasses()) {
            String className = clazz.getName();
            try {
                if (isAndroidComponent(clazz, "android.app.Activity")) {
                    activities.add(className);
                } else if (isAndroidComponent(clazz, "android.app.Service")) {
                    services.add(className);
                } else if (isAndroidComponent(clazz, "android.content.BroadcastReceiver")) {
                    receivers.add(className);
                } else if (isAndroidComponent(clazz, "android.content.ContentProvider")) {
                    providers.add(className);
                }
            } catch (Exception e) {
                // Ignore classes that can't be analyzed
            }
        }
        
        System.err.println("CALL-GRAPH-VERIFIER: Activities: " + activities.size());
        System.err.println("CALL-GRAPH-VERIFIER: Services: " + services.size());
        System.err.println("CALL-GRAPH-VERIFIER: BroadcastReceivers: " + receivers.size());
        System.err.println("CALL-GRAPH-VERIFIER: ContentProviders: " + providers.size());
        
        // Check for edges between different component types
        checkCrossComponentEdges(activities, services, receivers, providers);
    }
    
    /**
     * Check if a class extends a specific Android component
     */
    private boolean isAndroidComponent(SootClass clazz, String baseClassName) {
        try {
            SootClass baseClass = Scene.v().getSootClass(baseClassName);
            return Scene.v().getOrMakeFastHierarchy().isSubclass(clazz, baseClass);
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Check for edges between different Android component types
     */
    private void checkCrossComponentEdges(Set<String> activities, Set<String> services, 
                                        Set<String> receivers, Set<String> providers) {
        int activityToService = 0;
        int activityToReceiver = 0;
        int serviceToActivity = 0;
        int receiverToService = 0;
        // ... other combinations
        
        Iterator<Edge> allEdges = _callGraph.iterator();
        while (allEdges.hasNext()) {
            Edge edge = allEdges.next();
            
            String srcClassName = edge.getSrc().method().getDeclaringClass().getName();
            String tgtClassName = edge.getTgt().method().getDeclaringClass().getName();
            
            // Count cross-component edges
            if (activities.contains(srcClassName) && services.contains(tgtClassName)) {
                activityToService++;
            } else if (activities.contains(srcClassName) && receivers.contains(tgtClassName)) {
                activityToReceiver++;
            } else if (services.contains(srcClassName) && activities.contains(tgtClassName)) {
                serviceToActivity++;
            } else if (receivers.contains(srcClassName) && services.contains(tgtClassName)) {
                receiverToService++;
            }
        }
        
        System.err.println("CALL-GRAPH-VERIFIER: Activity -> Service edges: " + activityToService);
        System.err.println("CALL-GRAPH-VERIFIER: Activity -> Receiver edges: " + activityToReceiver);
        System.err.println("CALL-GRAPH-VERIFIER: Service -> Activity edges: " + serviceToActivity);
        System.err.println("CALL-GRAPH-VERIFIER: Receiver -> Service edges: " + receiverToService);
        
        int totalCrossComponentEdges = activityToService + activityToReceiver + 
                                      serviceToActivity + receiverToService;
        System.err.println("CALL-GRAPH-VERIFIER: Total cross-component edges: " + totalCrossComponentEdges);
        
        if (totalCrossComponentEdges == 0) {
            System.err.println("CALL-GRAPH-VERIFIER: WARNING - No cross-component edges found. " +
                              "ICC may not be working properly.");
        }
    }
    
    /**
     * Check for orphaned nodes (methods with no edges)
     */
    private void checkOrphanedNodes() {
        System.err.println("CALL-GRAPH-VERIFIER: === Orphaned Nodes Analysis ===");
        
        Set<SootMethod> applicationMethods = new HashSet<>();
        Set<MethodOrMethodContext> connectedMethods = new HashSet<>();
        
        // Collect all application methods
        for (SootClass clazz : Scene.v().getApplicationClasses()) {
            for (SootMethod method : clazz.getMethods()) {
                if (method.hasActiveBody()) {
                    applicationMethods.add(method);
                }
            }
        }
        
        // Collect all methods in call graph
        Iterator<Edge> allEdges = _callGraph.iterator();
        while (allEdges.hasNext()) {
            Edge edge = allEdges.next();
            connectedMethods.add(edge.getSrc());
            connectedMethods.add(edge.getTgt());
        }
        
        // Find orphaned application methods
        int orphanedCount = 0;
        for (SootMethod appMethod : applicationMethods) {
            boolean isConnected = false;
            for (MethodOrMethodContext connectedMethod : connectedMethods) {
                if (connectedMethod.method().equals(appMethod)) {
                    isConnected = true;
                    break;
                }
            }
            
            if (!isConnected) {
                orphanedCount++;
                if (orphanedCount <= 10) { // Limit output
                    System.err.println("CALL-GRAPH-VERIFIER: Orphaned application method: " + 
                                      appMethod.getSignature());
                }
            }
        }
        
        if (orphanedCount > 10) {
            System.err.println("CALL-GRAPH-VERIFIER: ... and " + (orphanedCount - 10) + " more orphaned methods");
        }
        
        System.err.println("CALL-GRAPH-VERIFIER: Total application methods: " + applicationMethods.size());
        System.err.println("CALL-GRAPH-VERIFIER: Connected application methods: " + 
                          (applicationMethods.size() - orphanedCount));
        System.err.println("CALL-GRAPH-VERIFIER: Orphaned application methods: " + orphanedCount);
        
        double connectionRatio = applicationMethods.size() > 0 ? 
                                (applicationMethods.size() - orphanedCount) * 100.0 / applicationMethods.size() : 0;
        System.err.println("CALL-GRAPH-VERIFIER: Connection ratio: " + String.format("%.1f%%", connectionRatio));
    }
    
    /**
     * Analyze connectivity between application and framework classes
     */
    private void analyzeApplicationFrameworkConnectivity() {
        System.err.println("CALL-GRAPH-VERIFIER: === Application-Framework Connectivity ===");
        
        int appToApp = 0;
        int appToFramework = 0;
        int frameworkToApp = 0;
        int frameworkToFramework = 0;
        
        Iterator<Edge> allEdges = _callGraph.iterator();
        while (allEdges.hasNext()) {
            Edge edge = allEdges.next();
            boolean srcIsApp = edge.getSrc().method().getDeclaringClass().isApplicationClass();
            boolean tgtIsApp = edge.getTgt().method().getDeclaringClass().isApplicationClass();
            
            if (srcIsApp && tgtIsApp) {
                appToApp++;
            } else if (srcIsApp && !tgtIsApp) {
                appToFramework++;
            } else if (!srcIsApp && tgtIsApp) {
                frameworkToApp++;
            } else {
                frameworkToFramework++;
            }
        }
        
        int totalEdges = appToApp + appToFramework + frameworkToApp + frameworkToFramework;
        
        System.err.println("CALL-GRAPH-VERIFIER: App -> App edges: " + appToApp + 
                          " (" + String.format("%.1f%%", appToApp * 100.0 / totalEdges) + ")");
        System.err.println("CALL-GRAPH-VERIFIER: App -> Framework edges: " + appToFramework + 
                          " (" + String.format("%.1f%%", appToFramework * 100.0 / totalEdges) + ")");
        System.err.println("CALL-GRAPH-VERIFIER: Framework -> App edges: " + frameworkToApp + 
                          " (" + String.format("%.1f%%", frameworkToApp * 100.0 / totalEdges) + ")");
        System.err.println("CALL-GRAPH-VERIFIER: Framework -> Framework edges: " + frameworkToFramework + 
                          " (" + String.format("%.1f%%", frameworkToFramework * 100.0 / totalEdges) + ")");
        
        if (frameworkToApp == 0) {
            System.err.println("CALL-GRAPH-VERIFIER: WARNING - No framework -> app edges found. " +
                              "Entry points may not be properly connected.");
        }
    }
    
    /**
     * Helper method to count edges from an iterator
     */
    private int countEdges(Iterator<Edge> edges) {
        int count = 0;
        while (edges.hasNext()) {
            edges.next();
            count++;
        }
        return count;
    }
    
    /**
     * Find a SootMethod in the call graph and return its context
     */
    private MethodOrMethodContext findMethodInCallGraph(SootMethod method) {
        Iterator<Edge> allEdges = _callGraph.iterator();
        while (allEdges.hasNext()) {
            Edge edge = allEdges.next();
            if (edge.getSrc().method().equals(method)) {
                return edge.getSrc();
            }
            if (edge.getTgt().method().equals(method)) {
                return edge.getTgt();
            }
        }
        return null;
    }
    
    /**
     * Quick connectivity check for specific entry point
     */
    public boolean isEntryPointConnected(MethodOrMethodContext entryPoint) {
        return _callGraph.edgesOutOf(entryPoint).hasNext() || _callGraph.edgesInto(entryPoint).hasNext();
    }
    
    /**
     * Count reachable methods from an entry point (BFS traversal)
     */
    public int countReachableMethods(MethodOrMethodContext entryPoint, int maxDepth) {
        Set<MethodOrMethodContext> visited = new HashSet<>();
        Queue<MethodOrMethodContext> queue = new LinkedList<>();
        Map<MethodOrMethodContext, Integer> depths = new HashMap<>();
        
        queue.add(entryPoint);
        visited.add(entryPoint);
        depths.put(entryPoint, 0);
        
        while (!queue.isEmpty()) {
            MethodOrMethodContext current = queue.poll();
            int currentDepth = depths.get(current);
            
            if (currentDepth >= maxDepth) {
                continue;
            }
            
            Iterator<Edge> outEdges = _callGraph.edgesOutOf(current);
            while (outEdges.hasNext()) {
                MethodOrMethodContext target = outEdges.next().getTgt();
                if (!visited.contains(target)) {
                    visited.add(target);
                    depths.put(target, currentDepth + 1);
                    queue.add(target);
                }
            }
        }
        
        return visited.size();
    }
}