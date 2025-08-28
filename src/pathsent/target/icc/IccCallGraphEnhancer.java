package pathsent.target.icc;

import pathsent.target.ManifestAnalysis;
import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.*;

import java.util.*;

/**
 * IccCallGraphEnhancer combines FlowDroid's IccTA approach with Amandroid's component 
 * summary approach to create explicit ICC edges in the call graph.
 * 
 * Key innovations:
 * - Static Intent analysis to identify ICC communication patterns
 * - Explicit edge creation from Intent senders to receivers
 * - Support for implicit Intent resolution using manifest data
 * - Integration with Amandroid-style component summaries
 * - Uses CallGraphModifier to actually add ICC edges to the call graph
 */
public class IccCallGraphEnhancer {
    private final ManifestAnalysis _manifestAnalysis;
    private final CallGraph _callGraph;
    private final CallGraphModifier _callGraphModifier;
    
    // ICC communication patterns discovered
    private final Set<IccCommunication> _iccCommunications = new HashSet<>();
    
    // Mapping from Intent actions to target components
    private final Map<String, Set<SootClass>> _actionToComponents = new HashMap<>();
    
    public IccCallGraphEnhancer(ManifestAnalysis manifestAnalysis, CallGraph callGraph) {
        _manifestAnalysis = manifestAnalysis;
        _callGraph = callGraph;
        _callGraphModifier = new CallGraphModifier(callGraph);
        buildActionToComponentMapping();
    }
    
    /**
     * Enhance call graph with explicit ICC edges
     */
    public void enhanceCallGraph() {
        System.err.println("ICC-ENHANCER: Starting ICC call graph enhancement");
        
        // Phase 1: Discover ICC communications from method bodies
        discoverIccCommunications();
        
        // Phase 2: Create explicit ICC edges
        createExplicitIccEdges();
        
        // Phase 3: Handle implicit Intent resolution
        handleImplicitIntentResolution();
        
        // Phase 4: Verify ICC edges were successfully added
        verifyIccEdges();
        
        // Phase 5: Print statistics about ICC edge addition
        _callGraphModifier.printStatistics();
        
        System.err.println("ICC-ENHANCER: Created " + _iccCommunications.size() + " ICC communication links");
        System.err.println("ICC-ENHANCER: ICC call graph enhancement completed");
    }
    
    /**
     * Build mapping from Intent actions to target components using manifest data
     */
    private void buildActionToComponentMapping() {
        System.err.println("ICC-ENHANCER: Building action-to-component mapping");
        
        Map<String, Set<String>> componentActions = _manifestAnalysis.getAllIntentActions();
        
        for (Map.Entry<String, Set<String>> entry : componentActions.entrySet()) {
            String componentName = entry.getKey();
            Set<String> actions = entry.getValue();
            
            if (Scene.v().containsClass(componentName)) {
                SootClass componentClass = Scene.v().getSootClass(componentName);
                
                for (String action : actions) {
                    _actionToComponents.computeIfAbsent(action, k -> new HashSet<>())
                                     .add(componentClass);
                }
            }
        }
        
        System.err.println("ICC-ENHANCER: Mapped " + _actionToComponents.size() + " actions to components");
    }
    
    /**
     * Discover ICC communications by analyzing method bodies
     */
    private void discoverIccCommunications() {
        System.err.println("ICC-ENHANCER: Discovering ICC communications from method bodies");
        
        int communicationCount = 0;
        
        // Analyze all application methods for ICC patterns
        for (SootClass clazz : Scene.v().getApplicationClasses()) {
            for (SootMethod method : clazz.getMethods()) {
                if (method.hasActiveBody()) {
                    communicationCount += discoverIccCommunicationsInMethod(method);
                }
            }
        }
        
        System.err.println("ICC-ENHANCER: Discovered " + communicationCount + " ICC communications");
    }
    
    /**
     * Discover ICC communications in a single method
     */
    private int discoverIccCommunicationsInMethod(SootMethod method) {
        int count = 0;
        JimpleBody body = (JimpleBody) method.getActiveBody();
        
        for (Unit unit : body.getUnits()) {
            if (unit instanceof InvokeStmt || unit instanceof AssignStmt) {
                InvokeExpr invokeExpr = null;
                
                if (unit instanceof InvokeStmt) {
                    invokeExpr = ((InvokeStmt) unit).getInvokeExpr();
                } else if (unit instanceof AssignStmt) {
                    Value rightOp = ((AssignStmt) unit).getRightOp();
                    if (rightOp instanceof InvokeExpr) {
                        invokeExpr = (InvokeExpr) rightOp;
                    }
                }
                
                if (invokeExpr != null) {
                    IccCommunication comm = analyzeInvokeForIcc(method, unit, invokeExpr);
                    if (comm != null) {
                        _iccCommunications.add(comm);
                        count++;
                        
                        System.err.println("ICC-ENHANCER: Found ICC: " + comm.getType() + 
                                          " from " + method.getSignature() + " to " + comm.getTargetAction());
                    }
                }
            }
        }
        
        return count;
    }
    
    /**
     * Analyze an invoke expression for ICC patterns
     */
    private IccCommunication analyzeInvokeForIcc(SootMethod sourceMethod, Unit unit, InvokeExpr invokeExpr) {
        String methodSig = invokeExpr.getMethod().getSignature();
        
        // Check for common ICC method patterns
        if (methodSig.contains("startActivity") || methodSig.contains("startActivityForResult")) {
            return analyzeStartActivity(sourceMethod, unit, invokeExpr);
        } else if (methodSig.contains("startService") || methodSig.contains("bindService")) {
            return analyzeStartService(sourceMethod, unit, invokeExpr);
        } else if (methodSig.contains("sendBroadcast") || methodSig.contains("sendOrderedBroadcast")) {
            return analyzeSendBroadcast(sourceMethod, unit, invokeExpr);
        } else if (methodSig.contains("query") || methodSig.contains("insert") || methodSig.contains("update") || methodSig.contains("delete")) {
            if (methodSig.contains("ContentResolver")) {
                return analyzeContentProvider(sourceMethod, unit, invokeExpr);
            }
        } else if (methodSig.contains("registerReceiver")) {
            return analyzeRegisterReceiver(sourceMethod, unit, invokeExpr);
        } else if (methodSig.contains("send") && methodSig.contains("Messenger")) {
            return analyzeMessengerSend(sourceMethod, unit, invokeExpr);
        }
        
        return null;
    }
    
    private IccCommunication analyzeStartActivity(SootMethod sourceMethod, Unit unit, InvokeExpr invokeExpr) {
        // Extract Intent parameter
        if (invokeExpr.getArgCount() > 0) {
            Value intentValue = invokeExpr.getArg(0);
            String action = extractIntentAction(sourceMethod.getActiveBody(), intentValue);
            
            if (action != null) {
                return new IccCommunication(sourceMethod, IccCommunication.Type.START_ACTIVITY, action, unit);
            }
        }
        return null;
    }
    
    private IccCommunication analyzeStartService(SootMethod sourceMethod, Unit unit, InvokeExpr invokeExpr) {
        if (invokeExpr.getArgCount() > 0) {
            Value intentValue = invokeExpr.getArg(0);
            String action = extractIntentAction(sourceMethod.getActiveBody(), intentValue);
            
            if (action != null) {
                return new IccCommunication(sourceMethod, IccCommunication.Type.START_SERVICE, action, unit);
            }
        }
        return null;
    }
    
    private IccCommunication analyzeSendBroadcast(SootMethod sourceMethod, Unit unit, InvokeExpr invokeExpr) {
        if (invokeExpr.getArgCount() > 0) {
            Value intentValue = invokeExpr.getArg(0);
            String action = extractIntentAction(sourceMethod.getActiveBody(), intentValue);
            
            if (action != null) {
                return new IccCommunication(sourceMethod, IccCommunication.Type.SEND_BROADCAST, action, unit);
            }
        }
        return null;
    }
    
    private IccCommunication analyzeContentProvider(SootMethod sourceMethod, Unit unit, InvokeExpr invokeExpr) {
        if (invokeExpr.getArgCount() > 0) {
            Value uriValue = invokeExpr.getArg(0);
            String authority = extractContentProviderAuthority(sourceMethod.getActiveBody(), uriValue);
            
            if (authority != null) {
                return new IccCommunication(sourceMethod, IccCommunication.Type.CONTENT_PROVIDER, authority, unit);
            }
        }
        return null;
    }
    
    private IccCommunication analyzeRegisterReceiver(SootMethod sourceMethod, Unit unit, InvokeExpr invokeExpr) {
        // Dynamic receiver registration creates implicit ICC communication
        return new IccCommunication(sourceMethod, IccCommunication.Type.REGISTER_RECEIVER, "DYNAMIC", unit);
    }
    
    private IccCommunication analyzeMessengerSend(SootMethod sourceMethod, Unit unit, InvokeExpr invokeExpr) {
        // Messenger communication between processes/services
        return new IccCommunication(sourceMethod, IccCommunication.Type.MESSENGER, "RPC", unit);
    }
    
    /**
     * Extract Intent action from Intent value using backward analysis
     */
    private String extractIntentAction(Body body, Value intentValue) {
        // Simple backward analysis to find Intent action
        if (intentValue instanceof Local) {
            Local intentLocal = (Local) intentValue;
            
            // Look for Intent constructor calls or setAction calls
            for (Unit unit : body.getUnits()) {
                if (unit instanceof AssignStmt) {
                    AssignStmt assignStmt = (AssignStmt) unit;
                    if (assignStmt.getLeftOp().equals(intentLocal)) {
                        Value rightOp = assignStmt.getRightOp();
                        
                        if (rightOp instanceof NewExpr) {
                            // Look for subsequent constructor call
                            continue;
                        } else if (rightOp instanceof InvokeExpr) {
                            InvokeExpr invoke = (InvokeExpr) rightOp;
                            if (invoke.getMethod().getName().equals("<init>") && invoke.getArgCount() > 0) {
                                Value actionArg = invoke.getArg(0);
                                if (actionArg instanceof StringConstant) {
                                    return ((StringConstant) actionArg).value;
                                }
                            }
                        }
                    }
                } else if (unit instanceof InvokeStmt) {
                    InvokeStmt invokeStmt = (InvokeStmt) unit;
                    InvokeExpr invoke = invokeStmt.getInvokeExpr();
                    
                    if (invoke instanceof VirtualInvokeExpr || invoke instanceof InterfaceInvokeExpr) {
                        Value base = ((InstanceInvokeExpr) invoke).getBase();
                        if (base.equals(intentLocal) && invoke.getMethod().getName().equals("setAction")) {
                            if (invoke.getArgCount() > 0) {
                                Value actionArg = invoke.getArg(0);
                                if (actionArg instanceof StringConstant) {
                                    return ((StringConstant) actionArg).value;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        return null;
    }
    
    /**
     * Extract ContentProvider authority from URI value
     */
    private String extractContentProviderAuthority(Body body, Value uriValue) {
        // Simplified authority extraction - in real implementation would need more sophisticated analysis
        if (uriValue instanceof StringConstant) {
            String uriString = ((StringConstant) uriValue).value;
            if (uriString.startsWith("content://")) {
                int authorityEnd = uriString.indexOf('/', 10);
                if (authorityEnd == -1) {
                    return uriString.substring(10);
                } else {
                    return uriString.substring(10, authorityEnd);
                }
            }
        }
        return null;
    }
    
    /**
     * Create explicit ICC edges in the call graph
     */
    private void createExplicitIccEdges() {
        System.err.println("ICC-ENHANCER: Creating explicit ICC edges");
        
        int edgeCount = 0;
        
        for (IccCommunication comm : _iccCommunications) {
            Set<SootClass> targetComponents = _actionToComponents.get(comm.getTargetAction());
            
            if (targetComponents != null) {
                for (SootClass targetComponent : targetComponents) {
                    SootMethod targetMethod = findIccEntryMethod(targetComponent, comm.getType());
                    if (targetMethod != null) {
                        createIccEdge(comm, targetMethod);
                        edgeCount++;
                        
                        System.err.println("ICC-ENHANCER: Created ICC edge: " + 
                                          comm.getSourceMethod().getSignature() + " -> " + 
                                          targetMethod.getSignature());
                    }
                }
            }
        }
        
        System.err.println("ICC-ENHANCER: Created " + edgeCount + " explicit ICC edges");
    }
    
    /**
     * Find the appropriate entry method for ICC communication in target component
     */
    private SootMethod findIccEntryMethod(SootClass targetComponent, IccCommunication.Type commType) {
        switch (commType) {
            case START_ACTIVITY:
                return targetComponent.getMethodUnsafe("void onCreate(android.os.Bundle)");
            case START_SERVICE:
                return targetComponent.getMethodUnsafe("int onStartCommand(android.content.Intent,int,int)");
            case SEND_BROADCAST:
                return targetComponent.getMethodUnsafe("void onReceive(android.content.Context,android.content.Intent)");
            case CONTENT_PROVIDER:
                // Could be query, insert, update, delete - use query as default entry
                return targetComponent.getMethodUnsafe("android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)");
            case REGISTER_RECEIVER:
                return targetComponent.getMethodUnsafe("void onReceive(android.content.Context,android.content.Intent)");
            case MESSENGER:
                return targetComponent.getMethodUnsafe("void handleMessage(android.os.Message)");
            default:
                return null;
        }
    }
    
    /**
     * Create an ICC edge in the call graph using CallGraphModifier
     */
    private void createIccEdge(IccCommunication comm, SootMethod targetMethod) {
        // Find existing MethodOrMethodContext objects from the call graph
        MethodOrMethodContext srcMethodContext = findMethodContext(comm.getSourceMethod());
        MethodOrMethodContext tgtMethodContext = findMethodContext(targetMethod);
        
        if (srcMethodContext != null && tgtMethodContext != null) {
            // Create synthetic edge in call graph
            Edge edge = new Edge(srcMethodContext, comm.getIccUnit(), tgtMethodContext, Kind.VIRTUAL);
            
            // Actually add the ICC edge to the call graph using reflection
            boolean success = _callGraphModifier.addIccEdge(edge);
            
            if (success) {
                System.err.println("ICC-ENHANCER: Successfully added ICC edge to call graph: " + 
                                  comm.getSourceMethod().getSignature() + " -> " + 
                                  targetMethod.getSignature());
            } else {
                System.err.println("ICC-ENHANCER: WARNING - Failed to add ICC edge to call graph: " + 
                                  comm.getSourceMethod().getSignature() + " -> " + 
                                  targetMethod.getSignature());
            }
        } else {
            System.err.println("ICC-ENHANCER: WARNING - Could not find method contexts for ICC edge: " + 
                              comm.getSourceMethod().getSignature() + " -> " + 
                              targetMethod.getSignature());
        }
        
        // Mark this communication with the target method for MultiComponentAnalysis
        comm.setTargetMethod(targetMethod);
    }
    
    /**
     * Find existing MethodOrMethodContext for a SootMethod in the call graph
     */
    private MethodOrMethodContext findMethodContext(SootMethod method) {
        // Search through existing call graph edges to find method contexts
        Iterator<MethodOrMethodContext> entryPoints = _callGraph.sourceMethods();
        while (entryPoints.hasNext()) {
            MethodOrMethodContext context = entryPoints.next();
            if (context.method().equals(method)) {
                return context;
            }
        }
        
        // Also check target methods
        for (SootClass clazz : Scene.v().getApplicationClasses()) {
            for (SootMethod classMethod : clazz.getMethods()) {
                if (classMethod.equals(method)) {
                    // Check if this method appears as a target in any existing edge
                    Iterator<Edge> allEdges = _callGraph.iterator();
                    while (allEdges.hasNext()) {
                        Edge edge = allEdges.next();
                        if (edge.getTgt().method().equals(method)) {
                            return edge.getTgt();
                        }
                        if (edge.getSrc().method().equals(method)) {
                            return edge.getSrc();
                        }
                    }
                }
            }
        }
        
        return null;
    }
    
    /**
     * Handle implicit Intent resolution for more comprehensive ICC coverage
     */
    private void handleImplicitIntentResolution() {
        System.err.println("ICC-ENHANCER: Handling implicit Intent resolution");
        
        // For implicit Intents without explicit actions, try to resolve based on:
        // 1. MIME types
        // 2. Categories  
        // 3. Data schemes
        // This is a placeholder for more sophisticated Intent resolution
        
        int implicitResolutions = 0;
        
        for (IccCommunication comm : _iccCommunications) {
            if (comm.getTargetAction() == null || comm.getTargetAction().isEmpty()) {
                // Try to resolve implicit Intent
                Set<SootClass> candidates = resolveImplicitIntent(comm);
                for (SootClass candidate : candidates) {
                    SootMethod targetMethod = findIccEntryMethod(candidate, comm.getType());
                    if (targetMethod != null) {
                        comm.setTargetMethod(targetMethod);
                        implicitResolutions++;
                    }
                }
            }
        }
        
        System.err.println("ICC-ENHANCER: Resolved " + implicitResolutions + " implicit Intents");
    }
    
    /**
     * Resolve implicit Intent to possible target components
     */
    private Set<SootClass> resolveImplicitIntent(IccCommunication comm) {
        Set<SootClass> candidates = new HashSet<>();
        
        // Simplified implicit resolution - match by component type
        for (SootClass clazz : Scene.v().getApplicationClasses()) {
            if (isCompatibleComponent(clazz, comm.getType())) {
                candidates.add(clazz);
            }
        }
        
        return candidates;
    }
    
    /**
     * Check if component is compatible with ICC communication type
     */
    private boolean isCompatibleComponent(SootClass clazz, IccCommunication.Type commType) {
        try {
            switch (commType) {
                case START_ACTIVITY:
                    return Scene.v().getOrMakeFastHierarchy().isSubclass(clazz, Scene.v().getSootClass("android.app.Activity"));
                case START_SERVICE:
                    return Scene.v().getOrMakeFastHierarchy().isSubclass(clazz, Scene.v().getSootClass("android.app.Service"));
                case SEND_BROADCAST:
                case REGISTER_RECEIVER:
                    return Scene.v().getOrMakeFastHierarchy().isSubclass(clazz, Scene.v().getSootClass("android.content.BroadcastReceiver"));
                case CONTENT_PROVIDER:
                    return Scene.v().getOrMakeFastHierarchy().isSubclass(clazz, Scene.v().getSootClass("android.content.ContentProvider"));
                case MESSENGER:
                    // Handler or Service that handles Messages
                    return Scene.v().getOrMakeFastHierarchy().isSubclass(clazz, Scene.v().getSootClass("android.app.Service")) ||
                           clazz.getName().contains("Handler");
                default:
                    return false;
            }
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Get all discovered ICC communications
     */
    public Set<IccCommunication> getIccCommunications() {
        return Collections.unmodifiableSet(_iccCommunications);
    }
    
    /**
     * Get the CallGraphModifier for inspection and verification
     */
    public CallGraphModifier getCallGraphModifier() {
        return _callGraphModifier;
    }
    
    /**
     * Verify that ICC edges were successfully added to the call graph
     */
    public void verifyIccEdges() {
        System.err.println("ICC-ENHANCER: Verifying ICC edges in call graph");
        
        int verifiedCount = 0;
        int totalCount = 0;
        
        for (IccCommunication comm : _iccCommunications) {
            if (comm.getTargetMethod() != null) {
                totalCount++;
                
                // Find existing method contexts for verification
                MethodOrMethodContext srcMethodContext = findMethodContext(comm.getSourceMethod());
                MethodOrMethodContext tgtMethodContext = findMethodContext(comm.getTargetMethod());
                
                if (srcMethodContext != null && tgtMethodContext != null) {
                    // Create edge for verification
                    Edge edge = new Edge(srcMethodContext, comm.getIccUnit(), tgtMethodContext, Kind.VIRTUAL);
                    
                    if (_callGraphModifier.verifyEdge(edge)) {
                        verifiedCount++;
                    }
                } else {
                    System.err.println("ICC-ENHANCER: Cannot verify edge - method contexts not found: " +
                                      comm.getSourceMethod().getSignature() + " -> " + 
                                      comm.getTargetMethod().getSignature());
                }
            }
        }
        
        System.err.println("ICC-ENHANCER: " + verifiedCount + "/" + totalCount + " ICC edges verified in call graph");
        
        if (verifiedCount < totalCount) {
            System.err.println("ICC-ENHANCER: WARNING - Some ICC edges may not be traversable during path finding");
        }
    }
    
    /**
     * Represents an ICC communication pattern
     */
    public static class IccCommunication {
        public enum Type {
            START_ACTIVITY, START_SERVICE, SEND_BROADCAST, CONTENT_PROVIDER, REGISTER_RECEIVER, MESSENGER
        }
        
        private final SootMethod sourceMethod;
        private final Type type;
        private final String targetAction;
        private final Unit iccUnit;
        private SootMethod targetMethod;
        
        public IccCommunication(SootMethod sourceMethod, Type type, String targetAction, Unit iccUnit) {
            this.sourceMethod = sourceMethod;
            this.type = type;
            this.targetAction = targetAction;
            this.iccUnit = iccUnit;
        }
        
        // Getters
        public SootMethod getSourceMethod() { return sourceMethod; }
        public Type getType() { return type; }
        public String getTargetAction() { return targetAction; }
        public Unit getIccUnit() { return iccUnit; }
        public SootMethod getTargetMethod() { return targetMethod; }
        
        public void setTargetMethod(SootMethod targetMethod) {
            this.targetMethod = targetMethod;
        }
        
        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (obj == null || getClass() != obj.getClass()) return false;
            IccCommunication that = (IccCommunication) obj;
            return Objects.equals(sourceMethod, that.sourceMethod) &&
                   type == that.type &&
                   Objects.equals(targetAction, that.targetAction) &&
                   Objects.equals(iccUnit, that.iccUnit);
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(sourceMethod, type, targetAction, iccUnit);
        }
        
        @Override
        public String toString() {
            return String.format("IccCommunication{%s: %s -> %s}", 
                               type, sourceMethod.getSignature(), targetAction);
        }
    }
}