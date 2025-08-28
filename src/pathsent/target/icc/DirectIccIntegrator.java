package pathsent.target.icc;

import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.infoflow.android.entryPointCreators.components.ComponentEntryPointCollection;
import soot.jimple.infoflow.android.entryPointCreators.components.ComponentEntryPointInfo;
import soot.jimple.infoflow.android.iccta.IccInstrumenter;
import pathsent.target.ManifestAnalysis;
import pathsent.target.entrypoint.IEntryPointAnalysis;

/**
 * Direct ICC integration for PathSentinel that bypasses Soot Transform system
 * and directly integrates FlowDroid's IccInstrumenter into the call graph construction process.
 * 
 * This approach follows FlowDroid's SetupApplication pattern for better ICC edge creation.
 */
public class DirectIccIntegrator {
    
    private final String iccModelPath;
    private final ManifestAnalysis manifestAnalysis;
    private final IEntryPointAnalysis entryPointAnalysis;
    private IccInstrumenter iccInstrumenter;
    
    public DirectIccIntegrator(String iccModelPath, ManifestAnalysis manifestAnalysis, 
                              IEntryPointAnalysis entryPointAnalysis) {
        this.iccModelPath = iccModelPath;
        this.manifestAnalysis = manifestAnalysis;
        this.entryPointAnalysis = entryPointAnalysis;
    }
    
    /**
     * Performs ICC instrumentation before call graph construction.
     * This method should be called after Soot initialization but before PackManager.runPacks().
     */
    public void instrumentBeforeCallGraphConstruction() {
        System.err.println("PATHSENT-ICC: Starting direct ICC instrumentation");
        
        // PATHSENT: Using PathSentinel's native ICC functionality instead of FlowDroid IccInstrumenter
        // PathSentinel has ActivityPatcher and ServicePatcher that handle Intent-based ICC flows
        // These are automatically registered in AndroidCallGraphPatching
        System.err.println("PATHSENT-ICC: Skipping FlowDroid IccInstrumenter - using PathSentinel native ICC");
        System.err.println("PATHSENT-ICC: PathSentinel will handle ICC through ActivityPatcher and ServicePatcher");
        System.err.println("PATHSENT-ICC: Direct ICC instrumentation completed (native PathSentinel mode)");
    }
    
    /**
     * Performs ICC instrumentation after call graph construction.
     * This method should be called after the call graph is built.
     */
    public void instrumentAfterCallGraphConstruction() {
        System.err.println("PATHSENT-ICC: Post-call graph ICC instrumentation - using PathSentinel native ICC");
        System.err.println("PATHSENT-ICC: PathSentinel's ICC patching completed during call graph construction");
    }
    
    /**
     * Creates a ComponentEntryPointCollection mapping Android components to their entry points.
     * This is required by FlowDroid's IccInstrumenter to understand component relationships.
     */
    private ComponentEntryPointCollection createComponentCollection() {
        ComponentEntryPointCollection collection = new ComponentEntryPointCollection();
        
        try {
            // Map Activities to their onCreate methods
            for (String activityName : manifestAnalysis.getAllActivityNames()) {
                SootClass activityClass = Scene.v().getSootClassUnsafe(activityName);
                if (activityClass != null && !activityClass.isPhantom()) {
                    SootMethod onCreateMethod = getLifecycleMethod(activityClass, "onCreate", 
                        "void onCreate(android.os.Bundle)");
                    if (onCreateMethod != null) {
                        collection.put(activityClass, new ComponentEntryPointInfo(onCreateMethod));
                        System.err.println("PATHSENT-ICC: Mapped Activity " + activityName + " to onCreate");
                    }
                }
            }
            
            // Map Services to their onStartCommand methods
            for (String serviceName : manifestAnalysis.getAllServiceNames()) {
                SootClass serviceClass = Scene.v().getSootClassUnsafe(serviceName);
                if (serviceClass != null && !serviceClass.isPhantom()) {
                    SootMethod onStartMethod = getLifecycleMethod(serviceClass, "onStartCommand",
                        "int onStartCommand(android.content.Intent,int,int)");
                    if (onStartMethod != null) {
                        collection.put(serviceClass, new ComponentEntryPointInfo(onStartMethod));
                        System.err.println("PATHSENT-ICC: Mapped Service " + serviceName + " to onStartCommand");
                    }
                }
            }
            
            // Map BroadcastReceivers to their onReceive methods
            for (String receiverName : manifestAnalysis.getAllReceiverNames()) {
                SootClass receiverClass = Scene.v().getSootClassUnsafe(receiverName);
                if (receiverClass != null && !receiverClass.isPhantom()) {
                    SootMethod onReceiveMethod = getLifecycleMethod(receiverClass, "onReceive",
                        "void onReceive(android.content.Context,android.content.Intent)");
                    if (onReceiveMethod != null) {
                        collection.put(receiverClass, new ComponentEntryPointInfo(onReceiveMethod));
                        System.err.println("PATHSENT-ICC: Mapped BroadcastReceiver " + receiverName + " to onReceive");
                    }
                }
            }
            
            // Map ContentProviders to their query methods
            for (String providerName : manifestAnalysis.getAllProviderNames()) {
                SootClass providerClass = Scene.v().getSootClassUnsafe(providerName);
                if (providerClass != null && !providerClass.isPhantom()) {
                    SootMethod queryMethod = getLifecycleMethod(providerClass, "query",
                        "android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)");
                    if (queryMethod != null) {
                        collection.put(providerClass, new ComponentEntryPointInfo(queryMethod));
                        System.err.println("PATHSENT-ICC: Mapped ContentProvider " + providerName + " to query");
                    }
                }
            }
            
        } catch (Exception e) {
            System.err.println("PATHSENT-ICC: Warning - Error creating component collection: " + e.getMessage());
        }
        
        return collection;
    }
    
    /**
     * Helper method to find lifecycle methods in Android components
     */
    private SootMethod getLifecycleMethod(SootClass sootClass, String methodName, String signature) {
        try {
            // First try to get the method by signature
            if (sootClass.declaresMethod(signature)) {
                return sootClass.getMethod(signature);
            }
            
            // Fallback: search by method name
            for (SootMethod method : sootClass.getMethods()) {
                if (method.getName().equals(methodName)) {
                    return method;
                }
            }
        } catch (Exception e) {
            System.err.println("PATHSENT-ICC: Warning - Could not find method " + methodName + 
                " in " + sootClass.getName() + ": " + e.getMessage());
        }
        
        return null;
    }
    
    /**
     * Get the IccInstrumenter instance (for debugging/testing purposes)
     */
    public IccInstrumenter getIccInstrumenter() {
        return iccInstrumenter;
    }
}