package pathsent.target.callgraph;

import pathsent.Output;
import pathsent.target.ManifestAnalysis;
import pathsent.target.icc.ComponentSummaryTable;
import pathsent.target.icc.IntentAnalysisHelper;
import pathsent.target.icc.IntentFilter;
import pathsent.target.icc.ICCCallerInfo;
import pathsent.target.icc.ICCCalleeInfo;

import soot.*;
import soot.jimple.*;
import pathsent.target.callgraph.CallGraphPatchingTag;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.LocalDefs;
import soot.toolkits.scalar.LocalUses;
import soot.util.Chain;

import java.util.*;

public class BroadcastReceiverPatcher extends IntentBasedCallGraphPatcher {
    private static final SootClass _contextClass = Scene.v().getSootClass(
            "android.content.Context");
    private static final String _sendBroadcastMethodSignature =
            "void sendBroadcast(android.content.Intent)";
    private static final String _sendOrderedBroadcastMethodSignature =
            "void sendOrderedBroadcast(android.content.Intent,java.lang.String)";
    private static final String _sendStickyBroadcastMethodSignature =
            "void sendStickyBroadcast(android.content.Intent)";
    private static final String _registerReceiverMethodSignature =
            "android.content.Intent registerReceiver(android.content.BroadcastReceiver,android.content.IntentFilter)";
    private static final String _registerReceiverWithPermissionMethodSignature =
            "android.content.Intent registerReceiver(android.content.BroadcastReceiver,android.content.IntentFilter,java.lang.String,android.os.Handler)";

    // Component summary tables for ICC analysis
    private final Map<SootClass, ComponentSummaryTable> componentSummaries = new HashMap<>();
    
    // Dynamic receivers discovered at runtime
    private final Set<SootClass> dynamicReceivers = new HashSet<>();

    public BroadcastReceiverPatcher(SootClass patchClass, ManifestAnalysis manifestAnalysis) {
        super(CallGraphPatchingTag.Kind.BroadcastReceiver, patchClass, manifestAnalysis);
    }

    @Override
    public boolean shouldPatch(final Body body, Stmt invokeStmt) {
        SootMethod invokedMethod = invokeStmt.getInvokeExpr().getMethod();
        if (!_cha.isClassSuperclassOfIncluding(_contextClass,
                invokedMethod.getDeclaringClass())) {
            return false;
        }

        String methodSig = invokedMethod.getSubSignature();
        if (methodSig.equals(_sendBroadcastMethodSignature) ||
            methodSig.equals(_sendOrderedBroadcastMethodSignature) ||
            methodSig.equals(_sendStickyBroadcastMethodSignature) ||
            methodSig.equals(_registerReceiverMethodSignature) ||
            methodSig.equals(_registerReceiverWithPermissionMethodSignature)) {
            return true;
        }

        return false;
    }

    @Override
    public void patch(final Body body, UnitGraph cfg, LocalDefs localDefs,
            LocalUses localUses, Stmt invokeStmt) {
        InvokeExpr invoke = invokeStmt.getInvokeExpr();
        String methodSig = invoke.getMethod().getSubSignature();
        
        if (methodSig.equals(_registerReceiverMethodSignature) || 
            methodSig.equals(_registerReceiverWithPermissionMethodSignature)) {
            // Handle dynamic receiver registration
            patchDynamicReceiverRegistration(body, cfg, localDefs, localUses, invokeStmt, invoke);
        } else {
            // Handle broadcast sending (sendBroadcast, sendOrderedBroadcast, etc.)
            patchBroadcastSending(body, cfg, localDefs, localUses, invokeStmt, invoke);
        }
    }
    
    private void patchDynamicReceiverRegistration(final Body body, UnitGraph cfg, 
            LocalDefs localDefs, LocalUses localUses, Stmt invokeStmt, InvokeExpr invoke) {
        System.err.println("PATHSENT-RECEIVER: Patching dynamic receiver registration: " + invoke);
        
        // Get the BroadcastReceiver and IntentFilter arguments
        Value receiverArg = invoke.getArg(0);
        Value filterArg = invoke.getArg(1);
        
        // Extract permission if present (4-parameter variant)
        Set<String> permissions = new HashSet<>();
        if (invoke.getArgCount() >= 3) {
            Value permissionArg = invoke.getArg(2);
            String permission = extractStringConstant(permissionArg, body, localDefs, localUses, invokeStmt);
            if (permission != null) {
                permissions.add(permission);
            }
        }
        
        // Find the concrete receiver classes
        List<SootClass> receiverClasses = findReceiverClassesFromValue(
                body, localDefs, localUses, invokeStmt, receiverArg);
        
        // Extract IntentFilter information
        Set<IntentFilter> intentFilters = extractIntentFiltersFromValue(
                body, localDefs, localUses, invokeStmt, filterArg);
        
        if (receiverClasses != null && !receiverClasses.isEmpty()) {
            for (SootClass receiverClass : receiverClasses) {
                // Mark as dynamically registered receiver
                dynamicReceivers.add(receiverClass);
                
                // Create component summary for this receiver
                ComponentSummaryTable summary = getOrCreateComponentSummary(receiverClass);
                ComponentSummaryTable.ICCSummary iccSummary = summary.getSummary(ComponentSummaryTable.Channel.ICC);
                
                // Add callee information for this dynamic receiver
                SootMethod onReceiveMethod = receiverClass.getMethodUnsafe("void onReceive(android.content.Context,android.content.Intent)");
                if (onReceiveMethod != null) {
                    ICCCalleeInfo.IntentCallee callee = new ICCCalleeInfo.IntentCallee(
                            receiverClass, true, permissions, intentFilters, onReceiveMethod);
                    iccSummary.addCallee(callee);
                }
                
                createReceiverBridgeMethod(receiverClass, "dynamic_registration", invokeStmt);
                System.err.println("PATHSENT-RECEIVER: Created dynamic registration bridge for: " + 
                    receiverClass.getName() + " with filters: " + intentFilters.size());
            }
        } else {
            System.err.println("PATHSENT-RECEIVER: Could not resolve dynamic receiver classes");
        }
    }
    
    private void patchBroadcastSending(final Body body, UnitGraph cfg,
            LocalDefs localDefs, LocalUses localUses, Stmt invokeStmt, InvokeExpr invoke) {
        System.err.println("PATHSENT-RECEIVER: Patching broadcast sending: " + invoke);
        
        // Get the Intent argument (first parameter for all sendBroadcast methods)
        Value intentArg = invoke.getArg(0);
        
        // Find target receivers based on Intent
        List<SootClass> targetReceivers = findTargetReceiversFromIntent(
                body, cfg, localDefs, localUses, invokeStmt, intentArg);
        
        if (targetReceivers != null && !targetReceivers.isEmpty()) {
            for (SootClass receiverClass : targetReceivers) {
                createReceiverBridgeMethod(receiverClass, "broadcast_intent", invokeStmt);
                System.err.println("PATHSENT-RECEIVER: Created broadcast bridge for: " + receiverClass.getName());
            }
        } else {
            // If we can't resolve specific receivers, create bridges for all manifest receivers
            System.err.println("PATHSENT-RECEIVER: Could not resolve target receivers, adding all manifest receivers");
            for (String receiverName : _manifestAnalysis.getAllReceiverNames()) {
                if (Scene.v().containsClass(receiverName)) {
                    SootClass receiverClass = Scene.v().getSootClass(receiverName);
                    createReceiverBridgeMethod(receiverClass, "broadcast_fallback", invokeStmt);
                }
            }
        }
    }
    
    private List<SootClass> findReceiverClassesFromValue(final Body body, 
            LocalDefs localDefs, LocalUses localUses, Stmt invokeStmt, Value receiverValue) {
        List<SootClass> receiverClasses = new ArrayList<>();
        
        if (receiverValue instanceof Local) {
            // TODO: Implement receiver class resolution from Local variable
            // This requires analyzing the constructor calls and assignments to find the actual receiver type
            System.err.println("PATHSENT-RECEIVER: Dynamic receiver analysis not fully implemented for Local: " + receiverValue);
        }
        
        return receiverClasses.isEmpty() ? null : receiverClasses;
    }
    
    private List<SootClass> findTargetReceiversFromIntent(final Body body, UnitGraph cfg,
            LocalDefs localDefs, LocalUses localUses, Stmt invokeStmt, Value intentValue) {
        
        // Use parent class method to find target classes based on Intent
        List<SootClass> targetClasses = findTargetClassesFromIntent(
                body, cfg, localDefs, localUses, invokeStmt, intentValue);
        
        if (targetClasses != null) {
            List<SootClass> receiverClasses = new ArrayList<>();
            for (SootClass clazz : targetClasses) {
                if (isBroadcastReceiver(clazz)) {
                    receiverClasses.add(clazz);
                }
            }
            return receiverClasses.isEmpty() ? null : receiverClasses;
        }
        
        return null;
    }
    
    private boolean isBroadcastReceiver(SootClass clazz) {
        try {
            return _cha.isClassSubclassOfIncluding(clazz, 
                    Scene.v().getSootClass("android.content.BroadcastReceiver"));
        } catch (Exception e) {
            return false;
        }
    }
    
    private void createReceiverBridgeMethod(SootClass receiverClass, String bridgeType, Stmt invokeStmt) {
        // Create a bridge method that calls the receiver's onReceive method
        String bridgeMethodName = "bridge_" + receiverClass.getName().replace(".", "_") + "_" + bridgeType;
        
        if (_patchClass.declaresMethodByName(bridgeMethodName)) {
            // Bridge already exists
            return;
        }
        
        // Create bridge method signature
        List<Type> paramTypes = new ArrayList<>();
        paramTypes.add(Scene.v().getRefType("android.content.Context"));
        paramTypes.add(Scene.v().getRefType("android.content.Intent"));
        
        SootMethod bridgeMethod = Scene.v().makeSootMethod(bridgeMethodName, paramTypes, VoidType.v());
        _patchClass.addMethod(bridgeMethod);
        
        // Create method body
        JimpleBody body = Jimple.v().newBody(bridgeMethod);
        bridgeMethod.setActiveBody(body);
        
        // Create locals
        Local receiverLocal = Jimple.v().newLocal("receiver", receiverClass.getType());
        Local contextLocal = Jimple.v().newLocal("context", Scene.v().getRefType("android.content.Context"));
        Local intentLocal = Jimple.v().newLocal("intent", Scene.v().getRefType("android.content.Intent"));
        
        body.getLocals().add(receiverLocal);
        body.getLocals().add(contextLocal);
        body.getLocals().add(intentLocal);
        
        // Create parameter assignments
        body.getUnits().add(Jimple.v().newIdentityStmt(contextLocal, 
                Jimple.v().newParameterRef(Scene.v().getRefType("android.content.Context"), 0)));
        body.getUnits().add(Jimple.v().newIdentityStmt(intentLocal, 
                Jimple.v().newParameterRef(Scene.v().getRefType("android.content.Intent"), 1)));
        
        // Create receiver instance
        body.getUnits().add(Jimple.v().newAssignStmt(receiverLocal, 
                Jimple.v().newNewExpr(receiverClass.getType())));
        
        // Call receiver constructor
        SootMethod constructor = receiverClass.getMethodUnsafe("void <init>()");
        if (constructor != null) {
            body.getUnits().add(Jimple.v().newInvokeStmt(
                    Jimple.v().newSpecialInvokeExpr(receiverLocal, constructor.makeRef())));
        }
        
        // Call onReceive method
        SootMethod onReceiveMethod = receiverClass.getMethodUnsafe("void onReceive(android.content.Context,android.content.Intent)");
        if (onReceiveMethod != null) {
            List<Value> args = new ArrayList<>();
            args.add(contextLocal);
            args.add(intentLocal);
            
            body.getUnits().add(Jimple.v().newInvokeStmt(
                    Jimple.v().newVirtualInvokeExpr(receiverLocal, onReceiveMethod.makeRef(), args)));
        }
        
        // Add return statement
        body.getUnits().add(Jimple.v().newReturnVoidStmt());
        
        // Tag the invoke statement for call graph construction
        invokeStmt.addTag(new CallGraphPatchingTag(_kind, bridgeMethod));
        
        System.err.println("PATHSENT-RECEIVER: Created bridge method: " + bridgeMethod.getSignature());
    }
    
    /**
     * Get or create component summary table for the given class
     */
    private ComponentSummaryTable getOrCreateComponentSummary(SootClass component) {
        return componentSummaries.computeIfAbsent(component, ComponentSummaryTable::new);
    }
    
    /**
     * Extract IntentFilter information from IntentFilter value
     */
    private Set<IntentFilter> extractIntentFiltersFromValue(final Body body, LocalDefs localDefs, 
            LocalUses localUses, Stmt invokeStmt, Value filterValue) {
        Set<IntentFilter> filters = new HashSet<>();
        
        if (filterValue instanceof Local) {
            Local filterLocal = (Local) filterValue;
            
            // Trace back the definitions of the IntentFilter
            for (Unit unit : localDefs.getDefsOfAt(filterLocal, invokeStmt)) {
                if (unit instanceof AssignStmt) {
                    AssignStmt assign = (AssignStmt) unit;
                    Value rightOp = assign.getRightOp();
                    
                    if (rightOp instanceof NewExpr) {
                        // New IntentFilter() - analyze its usage
                        IntentFilter filter = analyzeIntentFilterUsage(body, filterLocal, unit);
                        if (filter != null) {
                            filters.add(filter);
                        }
                    }
                }
            }
        }
        
        return filters;
    }
    
    /**
     * Analyze IntentFilter usage to extract actions, categories, data, etc.
     */
    private IntentFilter analyzeIntentFilterUsage(Body body, Local filterLocal, Unit startUnit) {
        IntentFilter filter = new IntentFilter("BroadcastReceiver");
        
        // Look for method calls on the IntentFilter
        for (Unit unit : body.getUnits()) {
            if (unit instanceof InvokeStmt) {
                InvokeStmt invoke = (InvokeStmt) unit;
                if (invoke.getInvokeExpr() instanceof InstanceInvokeExpr) {
                    InstanceInvokeExpr instanceInvoke = (InstanceInvokeExpr) invoke.getInvokeExpr();
                    
                    if (instanceInvoke.getBase().equals(filterLocal)) {
                        String methodName = instanceInvoke.getMethod().getName();
                        
                        switch (methodName) {
                            case "addAction":
                                if (instanceInvoke.getArgCount() > 0) {
                                    String action = extractStringConstant(instanceInvoke.getArg(0), body, null, null, unit);
                                    if (action != null) {
                                        filter.addAction(action);
                                    } else {
                                        filter.addAction("ANY");
                                    }
                                }
                                break;
                            case "addCategory":
                                if (instanceInvoke.getArgCount() > 0) {
                                    String category = extractStringConstant(instanceInvoke.getArg(0), body, null, null, unit);
                                    if (category != null) {
                                        filter.addCategory(category);
                                    } else {
                                        filter.addCategory("ANY");
                                    }
                                }
                                break;
                            case "addDataScheme":
                                if (instanceInvoke.getArgCount() > 0) {
                                    String scheme = extractStringConstant(instanceInvoke.getArg(0), body, null, null, unit);
                                    if (scheme != null) {
                                        IntentAnalysisHelper.UriData uriData = new IntentAnalysisHelper.UriData();
                                        uriData.setScheme(scheme);
                                        filter.addData(uriData);
                                    }
                                }
                                break;
                        }
                    }
                }
            }
        }
        
        return filter;
    }
    
    /**
     * Extract string constant from a value, with basic backtracking
     */
    private String extractStringConstant(Value value, Body body, LocalDefs localDefs, 
            LocalUses localUses, Unit currentUnit) {
        if (value instanceof StringConstant) {
            return ((StringConstant) value).value;
        } else if (value instanceof Local && localDefs != null) {
            Local local = (Local) value;
            for (Unit unit : localDefs.getDefsOfAt(local, currentUnit)) {
                if (unit instanceof AssignStmt) {
                    AssignStmt assign = (AssignStmt) unit;
                    Value rightOp = assign.getRightOp();
                    if (rightOp instanceof StringConstant) {
                        return ((StringConstant) rightOp).value;
                    }
                }
            }
        }
        return null;
    }
    
    /**
     * Get all dynamic receivers discovered during analysis
     */
    public Set<SootClass> getDynamicReceivers() {
        return Collections.unmodifiableSet(dynamicReceivers);
    }
    
    /**
     * Get component summaries for ICC analysis
     */
    public Map<SootClass, ComponentSummaryTable> getComponentSummaries() {
        return Collections.unmodifiableMap(componentSummaries);
    }
}