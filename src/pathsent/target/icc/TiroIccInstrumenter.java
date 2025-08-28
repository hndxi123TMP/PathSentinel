package pathsent.target.icc;

import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Transform;
import soot.SceneTransformer;
import soot.jimple.infoflow.android.entryPointCreators.components.ComponentEntryPointCollection;
import soot.jimple.infoflow.android.entryPointCreators.components.ComponentEntryPointInfo;
import soot.jimple.infoflow.android.iccta.IccInstrumenter;
import pathsent.target.ManifestAnalysis;
import pathsent.target.entrypoint.IEntryPointAnalysis;
import java.util.Map;

/**
 * PathSentinel adapter for FlowDroid's IccInstrumenter that integrates ICC instrumentation
 * into PathSentinel's analysis pipeline. This class bridges PathSentinel's custom entry point analysis
 * with FlowDroid's ICC capabilities.
 */
public class TiroIccInstrumenter extends SceneTransformer {
    
    private final String iccModelPath;
    private final ManifestAnalysis manifestAnalysis;
    private final IEntryPointAnalysis entryPointAnalysis;
    private IccInstrumenter iccInstrumenter;
    
    public TiroIccInstrumenter(String iccModelPath, ManifestAnalysis manifestAnalysis, 
                              IEntryPointAnalysis entryPointAnalysis) {
        this.iccModelPath = iccModelPath;
        this.manifestAnalysis = manifestAnalysis;
        this.entryPointAnalysis = entryPointAnalysis;
    }
    
    @Override
    protected void internalTransform(String phaseName, Map<String, String> options) {
        System.err.println("PATHSENT-ICC: *** internalTransform() CALLED with phase: " + phaseName + " ***");
        System.err.println("PATHSENT-ICC: Starting ICC instrumentation phase");
        
        try {
            // Create component to entry point mapping for ICC instrumentation
            ComponentEntryPointCollection componentCollection = createComponentCollection();
            
            // Get the dummy main class from entry point analysis
            SootClass dummyMainClass = entryPointAnalysis.getDummyMainMethod().getDeclaringClass();
            
            // Create the ICC instrumenter
            iccInstrumenter = new IccInstrumenter(iccModelPath, dummyMainClass, componentCollection);
            
            // Perform ICC instrumentation before call graph construction
            System.err.println("PATHSENT-ICC: Calling IccInstrumenter.onBeforeCallgraphConstruction()");
            iccInstrumenter.onBeforeCallgraphConstruction();
            
            System.err.println("PATHSENT-ICC: ICC instrumentation completed successfully");
            
        } catch (Exception e) {
            System.err.println("PATHSENT-ICC: Error during ICC instrumentation: " + e.getMessage());
            e.printStackTrace();
            // Don't fail the analysis if ICC instrumentation fails
        }
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
     * Creates a Soot Transform that can be added to the wjpp pack for ICC instrumentation
     */
    public static Transform createTransform(String iccModelPath, ManifestAnalysis manifestAnalysis,
                                          IEntryPointAnalysis entryPointAnalysis) {
        return new Transform("wjpp.TiroIccInstrumenter", 
            new TiroIccInstrumenter(iccModelPath, manifestAnalysis, entryPointAnalysis));
    }
}