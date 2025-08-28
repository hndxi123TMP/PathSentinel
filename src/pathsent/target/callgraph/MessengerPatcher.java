package pathsent.target.callgraph;

import pathsent.target.ManifestAnalysis;
import pathsent.target.icc.ComponentSummaryTable;
import pathsent.target.icc.ICCCallerInfo;
import pathsent.target.icc.ICCCalleeInfo;

import soot.*;
import soot.jimple.*;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.LocalDefs;
import soot.toolkits.scalar.LocalUses;

import java.util.*;

/**
 * Patches call graph for Android Messenger/Handler RPC communication patterns
 * Based on Amandroid's messenger RPC analysis
 */
public class MessengerPatcher extends CallGraphPatcher {
    private static final SootClass _messengerClass = Scene.v().getSootClass("android.os.Messenger");
    private static final SootClass _handlerClass = Scene.v().getSootClass("android.os.Handler");
    private static final SootClass _messageClass = Scene.v().getSootClass("android.os.Message");
    
    private static final String _sendMessageSignature = "void send(android.os.Message)";
    private static final String _handleMessageSignature = "void handleMessage(android.os.Message)";
    
    // Component summary tables for RPC analysis
    private final Map<SootClass, ComponentSummaryTable> componentSummaries = new HashMap<>();
    private final ManifestAnalysis _manifestAnalysis;

    public MessengerPatcher(SootClass patchClass, ManifestAnalysis manifestAnalysis) {
        super(CallGraphPatchingTag.Kind.Messenger, patchClass);
        _manifestAnalysis = manifestAnalysis;
    }

    @Override
    public boolean shouldPatch(final Body body, Stmt invokeStmt) {
        InvokeExpr invoke = invokeStmt.getInvokeExpr();
        SootMethod invokedMethod = invoke.getMethod();
        
        // Check for Messenger.send() calls
        if (_cha.isClassSuperclassOfIncluding(_messengerClass, invokedMethod.getDeclaringClass()) &&
            invokedMethod.getSubSignature().equals(_sendMessageSignature)) {
            return true;
        }
        
        // Check for Handler.handleMessage() implementations
        if (_cha.isClassSuperclassOfIncluding(_handlerClass, invokedMethod.getDeclaringClass()) &&
            invokedMethod.getSubSignature().equals(_handleMessageSignature)) {
            return true;
        }
        
        return false;
    }

    @Override
    public void patch(final Body body, UnitGraph cfg, LocalDefs localDefs, 
            LocalUses localUses, Stmt invokeStmt) {
        InvokeExpr invoke = invokeStmt.getInvokeExpr();
        SootMethod invokedMethod = invoke.getMethod();
        String methodSig = invokedMethod.getSubSignature();
        
        if (methodSig.equals(_sendMessageSignature)) {
            // Handle Messenger.send() -> Handler.handleMessage() communication
            patchMessengerSend(body, cfg, localDefs, localUses, invokeStmt, invoke);
        } else if (methodSig.equals(_handleMessageSignature)) {
            // Register Handler.handleMessage() as RPC callee
            patchHandlerReceive(body, cfg, localDefs, localUses, invokeStmt, invoke);
        }
    }
    
    /**
     * Patch Messenger.send() calls to connect to Handler.handleMessage()
     */
    private void patchMessengerSend(final Body body, UnitGraph cfg, LocalDefs localDefs,
            LocalUses localUses, Stmt invokeStmt, InvokeExpr invoke) {
        System.err.println("PATHSENT-MESSENGER: Patching Messenger.send(): " + invoke);
        
        // Get the Message argument
        Value messageArg = invoke.getArg(0);
        
        // Find the target handlers for this messenger
        List<SootClass> targetHandlers = findTargetHandlers(body, localDefs, localUses, invokeStmt, invoke);
        
        if (targetHandlers != null && !targetHandlers.isEmpty()) {
            for (SootClass handlerClass : targetHandlers) {
                // Create RPC caller info
                SootClass callerComponent = body.getMethod().getDeclaringClass();
                String messageType = extractMessageType(messageArg, body, localDefs, localUses, invokeStmt);
                
                ICCCallerInfo.MessengerCaller caller = new ICCCallerInfo.MessengerCaller(
                        callerComponent, body.getMethod(), invokeStmt, messageType);
                
                // Add to component summary
                ComponentSummaryTable summary = getOrCreateComponentSummary(callerComponent);
                ComponentSummaryTable.RPCSummary rpcSummary = summary.getSummary(ComponentSummaryTable.Channel.RPC);
                rpcSummary.addCaller(caller);
                
                // Create bridge method to Handler.handleMessage()
                createMessengerBridgeMethod(handlerClass, messageType, invokeStmt);
                System.err.println("PATHSENT-MESSENGER: Created bridge for: " + handlerClass.getName());
            }
        } else {
            // Fallback: create bridges for all known Handler subclasses
            System.err.println("PATHSENT-MESSENGER: Could not resolve target handlers, using fallback");
            for (SootClass handlerSubclass : findAllHandlerSubclasses()) {
                createMessengerBridgeMethod(handlerSubclass, "unknown", invokeStmt);
            }
        }
    }
    
    /**
     * Register Handler.handleMessage() implementations as RPC callees
     */
    private void patchHandlerReceive(final Body body, UnitGraph cfg, LocalDefs localDefs,
            LocalUses localUses, Stmt invokeStmt, InvokeExpr invoke) {
        System.err.println("PATHSENT-MESSENGER: Registering Handler.handleMessage(): " + invoke);
        
        SootClass handlerClass = body.getMethod().getDeclaringClass();
        SootMethod handleMessageMethod = body.getMethod();
        
        // Create RPC callee info
        ICCCalleeInfo.MessengerCallee callee = new ICCCalleeInfo.MessengerCallee(
                handlerClass, true, new HashSet<>(), handleMessageMethod);
        
        // Add to component summary
        ComponentSummaryTable summary = getOrCreateComponentSummary(handlerClass);
        ComponentSummaryTable.RPCSummary rpcSummary = summary.getSummary(ComponentSummaryTable.Channel.RPC);
        rpcSummary.addCallee(callee);
        
        System.err.println("PATHSENT-MESSENGER: Registered handler callee: " + handlerClass.getName());
    }
    
    /**
     * Find target Handler classes for a Messenger.send() call
     */
    private List<SootClass> findTargetHandlers(final Body body, LocalDefs localDefs,
            LocalUses localUses, Stmt invokeStmt, InvokeExpr invoke) {
        List<SootClass> handlers = new ArrayList<>();
        
        // The Messenger object should have been constructed with a Handler
        // This requires more sophisticated points-to analysis to resolve properly
        // For now, we use a simplified heuristic
        
        Value messengerBase = null;
        if (invoke instanceof InstanceInvokeExpr) {
            messengerBase = ((InstanceInvokeExpr) invoke).getBase();
        }
        
        if (messengerBase instanceof Local) {
            // Trace back to find Handler used in Messenger construction
            Local messengerLocal = (Local) messengerBase;
            handlers.addAll(findHandlerFromMessengerConstruction(body, localDefs, localUses, invokeStmt, messengerLocal));
        }
        
        return handlers;
    }
    
    /**
     * Find Handler used in Messenger construction
     */
    private List<SootClass> findHandlerFromMessengerConstruction(final Body body, LocalDefs localDefs,
            LocalUses localUses, Stmt invokeStmt, Local messengerLocal) {
        List<SootClass> handlers = new ArrayList<>();
        
        for (Unit unit : localDefs.getDefsOfAt(messengerLocal, invokeStmt)) {
            if (unit instanceof AssignStmt) {
                AssignStmt assign = (AssignStmt) unit;
                Value rightOp = assign.getRightOp();
                
                if (rightOp instanceof NewExpr) {
                    // Look for Messenger constructor calls
                    for (Unit nextUnit : body.getUnits()) {
                        if (nextUnit instanceof InvokeStmt) {
                            InvokeStmt constructorInvoke = (InvokeStmt) nextUnit;
                            InvokeExpr constructorExpr = constructorInvoke.getInvokeExpr();
                            
                            if (constructorExpr instanceof SpecialInvokeExpr) {
                                SpecialInvokeExpr specialInvoke = (SpecialInvokeExpr) constructorExpr;
                                
                                if (specialInvoke.getBase().equals(messengerLocal) &&
                                    specialInvoke.getMethod().getName().equals("<init>") &&
                                    specialInvoke.getArgCount() > 0) {
                                    
                                    // First argument should be Handler
                                    Value handlerArg = specialInvoke.getArg(0);
                                    if (handlerArg instanceof Local) {
                                        SootClass handlerClass = findHandlerClassFromLocal(
                                                body, localDefs, localUses, constructorInvoke, (Local) handlerArg);
                                        if (handlerClass != null) {
                                            handlers.add(handlerClass);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        return handlers;
    }
    
    /**
     * Find Handler class from a Local variable
     */
    private SootClass findHandlerClassFromLocal(final Body body, LocalDefs localDefs,
            LocalUses localUses, Stmt stmt, Local handlerLocal) {
        for (Unit unit : localDefs.getDefsOfAt(handlerLocal, stmt)) {
            if (unit instanceof AssignStmt) {
                AssignStmt assign = (AssignStmt) unit;
                Value rightOp = assign.getRightOp();
                
                if (rightOp instanceof NewExpr) {
                    NewExpr newExpr = (NewExpr) rightOp;
                    SootClass handlerClass = newExpr.getBaseType().getSootClass();
                    
                    if (_cha.isClassSubclassOfIncluding(handlerClass, _handlerClass)) {
                        return handlerClass;
                    }
                }
            }
        }
        
        return null;
    }
    
    /**
     * Extract message type from Message object
     */
    private String extractMessageType(Value messageArg, final Body body, LocalDefs localDefs,
            LocalUses localUses, Stmt invokeStmt) {
        if (messageArg instanceof Local) {
            // Look for message.what = constant assignments
            Local messageLocal = (Local) messageArg;
            
            for (Unit unit : body.getUnits()) {
                if (unit instanceof AssignStmt) {
                    AssignStmt assign = (AssignStmt) unit;
                    Value leftOp = assign.getLeftOp();
                    
                    if (leftOp instanceof InstanceFieldRef) {
                        InstanceFieldRef fieldRef = (InstanceFieldRef) leftOp;
                        
                        if (fieldRef.getBase().equals(messageLocal) && 
                            fieldRef.getField().getName().equals("what")) {
                            
                            Value rightOp = assign.getRightOp();
                            if (rightOp instanceof IntConstant) {
                                return String.valueOf(((IntConstant) rightOp).value);
                            }
                        }
                    }
                }
            }
        }
        
        return "unknown";
    }
    
    /**
     * Find all Handler subclasses in the application
     */
    private List<SootClass> findAllHandlerSubclasses() {
        List<SootClass> handlerSubclasses = new ArrayList<>();
        
        for (SootClass clazz : Scene.v().getApplicationClasses()) {
            if (_cha.isClassSubclassOfIncluding(clazz, _handlerClass)) {
                handlerSubclasses.add(clazz);
            }
        }
        
        return handlerSubclasses;
    }
    
    /**
     * Create bridge method from Messenger.send() to Handler.handleMessage()
     */
    private void createMessengerBridgeMethod(SootClass handlerClass, String messageType, Stmt invokeStmt) {
        String bridgeMethodName = "bridge_messenger_" + 
                handlerClass.getName().replace(".", "_") + "_" + messageType;
        
        if (_patchClass.declaresMethodByName(bridgeMethodName)) {
            // Bridge already exists
            return;
        }
        
        // Create bridge method signature
        List<Type> paramTypes = new ArrayList<>();
        paramTypes.add(Scene.v().getRefType("android.os.Message"));
        
        SootMethod bridgeMethod = Scene.v().makeSootMethod(bridgeMethodName, paramTypes, VoidType.v());
        _patchClass.addMethod(bridgeMethod);
        
        // Create method body
        JimpleBody body = Jimple.v().newBody(bridgeMethod);
        bridgeMethod.setActiveBody(body);
        
        // Create locals
        Local handlerLocal = Jimple.v().newLocal("handler", handlerClass.getType());
        Local messageLocal = Jimple.v().newLocal("message", Scene.v().getRefType("android.os.Message"));
        
        body.getLocals().add(handlerLocal);
        body.getLocals().add(messageLocal);
        
        // Create parameter assignment
        body.getUnits().add(Jimple.v().newIdentityStmt(messageLocal, 
                Jimple.v().newParameterRef(Scene.v().getRefType("android.os.Message"), 0)));
        
        // Create handler instance
        body.getUnits().add(Jimple.v().newAssignStmt(handlerLocal, 
                Jimple.v().newNewExpr(handlerClass.getType())));
        
        // Call handler constructor
        SootMethod constructor = handlerClass.getMethodUnsafe("void <init>()");
        if (constructor != null) {
            body.getUnits().add(Jimple.v().newInvokeStmt(
                    Jimple.v().newSpecialInvokeExpr(handlerLocal, constructor.makeRef())));
        }
        
        // Call handleMessage method
        SootMethod handleMessageMethod = handlerClass.getMethodUnsafe(_handleMessageSignature);
        if (handleMessageMethod != null) {
            List<Value> args = Collections.singletonList(messageLocal);
            body.getUnits().add(Jimple.v().newInvokeStmt(
                    Jimple.v().newVirtualInvokeExpr(handlerLocal, handleMessageMethod.makeRef(), args)));
        }
        
        // Add return statement
        body.getUnits().add(Jimple.v().newReturnVoidStmt());
        
        // Tag the invoke statement for call graph construction
        invokeStmt.addTag(new CallGraphPatchingTag(_kind, bridgeMethod));
        
        System.err.println("PATHSENT-MESSENGER: Created bridge method: " + bridgeMethod.getSignature());
    }
    
    /**
     * Get or create component summary table for the given class
     */
    private ComponentSummaryTable getOrCreateComponentSummary(SootClass component) {
        return componentSummaries.computeIfAbsent(component, ComponentSummaryTable::new);
    }
    
    /**
     * Get component summaries for RPC analysis
     */
    public Map<SootClass, ComponentSummaryTable> getComponentSummaries() {
        return Collections.unmodifiableMap(componentSummaries);
    }
}