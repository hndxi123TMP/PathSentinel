package pathsent.target.entrypoint;

import pathsent.target.ManifestAnalysis;
import soot.*;
import soot.jimple.Jimple;
import soot.jimple.JimpleBody;

import java.util.*;

/**
 * Creates direct entry points for public test methods in Activities
 * This ensures test methods are analyzed as separate entry points
 * rather than only being reachable through lifecycle methods
 */
public class DirectMethodEntryPoints {
    private final ManifestAnalysis _manifestAnalysis;
    private final Set<MethodOrMethodContext> _directEntryPoints = new HashSet<>();
    
    public DirectMethodEntryPoints(ManifestAnalysis manifestAnalysis) {
        _manifestAnalysis = manifestAnalysis;
        createDirectEntryPoints();
    }
    
    /**
     * Create direct entry points for all public test methods in Activities
     */
    private void createDirectEntryPoints() {
        System.err.println("DIRECT ENTRYPOINTS: Creating direct entry points for test methods");
        
        for (String activityName : _manifestAnalysis.getAllActivityNames()) {
            if (Scene.v().containsClass(activityName)) {
                SootClass activityClass = Scene.v().getSootClass(activityName);
                createDirectTestMethodEntryPoints(activityClass);
            }
        }
        
        System.err.println("DIRECT ENTRYPOINTS: Created " + _directEntryPoints.size() + " direct entry points");
    }
    
    /**
     * Create direct entry points for test methods in an Activity
     */
    private void createDirectTestMethodEntryPoints(SootClass activityClass) {
        System.err.println("DIRECT ENTRYPOINTS: Analyzing " + activityClass.getName());
        
        List<SootMethod> testMethods = new ArrayList<>();
        for (SootMethod method : activityClass.getMethods()) {
            if (method.isPublic() && !method.isConstructor() && !method.isStaticInitializer()) {
                String methodName = method.getName();
                
                // Look for test methods or methods that directly manipulate files
                if (methodName.startsWith("test") || 
                    methodName.contains("hijacking") || 
                    methodName.contains("traversal") || 
                    methodName.contains("execution")) {
                    
                    testMethods.add(method);
                    _directEntryPoints.add(method);
                    
                    System.err.println("DIRECT ENTRYPOINTS: Added direct entry point: " + method.getSignature());
                }
            }
        }
        
        // Skip synthetic wrapper creation for test-focused mode to avoid path inflation
        // createTestMethodWrappers(activityClass, testMethods);
        
        System.err.println("DIRECT ENTRYPOINTS: " + activityClass.getName() + " - created " + testMethods.size() + " direct entry points");
    }
    
    /**
     * Create wrapper methods that properly initialize Activity context before calling test methods
     */
    private void createTestMethodWrappers(SootClass activityClass, List<SootMethod> testMethods) {
        if (testMethods.isEmpty()) {
            return;
        }
        
        System.err.println("DIRECT ENTRYPOINTS: Creating test method wrappers for " + activityClass.getName());
        
        try {
            for (SootMethod testMethod : testMethods) {
                String wrapperName = "directEntry_" + testMethod.getName();
                
                // Create wrapper method
                SootMethod wrapperMethod = Scene.v().makeSootMethod(wrapperName,
                    new ArrayList<>(), VoidType.v(), Modifier.PUBLIC | Modifier.STATIC);
                activityClass.addMethod(wrapperMethod);
                
                // Create method body
                JimpleBody body = Jimple.v().newBody(wrapperMethod);
                wrapperMethod.setActiveBody(body);
                
                // Create Activity instance
                String instanceName = "activityInstance";
                Local instanceLocal = Jimple.v().newLocal(instanceName, activityClass.getType());
                body.getLocals().add(instanceLocal);
                
                // New instance
                body.getUnits().add(Jimple.v().newAssignStmt(
                    instanceLocal, 
                    Jimple.v().newNewExpr(activityClass.getType())));
                
                // Call constructor
                SootMethod constructor = activityClass.getMethodUnsafe("void <init>()");
                if (constructor != null) {
                    body.getUnits().add(Jimple.v().newInvokeStmt(
                        Jimple.v().newSpecialInvokeExpr(instanceLocal, constructor.makeRef())));
                }
                
                // Call onCreate to initialize Activity
                SootMethod onCreateMethod = activityClass.getMethodUnsafe("void onCreate(android.os.Bundle)");
                if (onCreateMethod != null) {
                    Local bundleLocal = Jimple.v().newLocal("bundle", 
                        RefType.v("android.os.Bundle"));
                    body.getLocals().add(bundleLocal);
                    body.getUnits().add(Jimple.v().newAssignStmt(bundleLocal, 
                        soot.jimple.NullConstant.v()));
                    
                    body.getUnits().add(Jimple.v().newInvokeStmt(
                        Jimple.v().newVirtualInvokeExpr(instanceLocal, onCreateMethod.makeRef(),
                            Collections.singletonList(bundleLocal))));
                }
                
                // Call the test method
                List<Local> paramLocals = new ArrayList<>();
                for (int i = 0; i < testMethod.getParameterCount(); i++) {
                    Type paramType = testMethod.getParameterType(i);
                    String paramLocalName = "param_" + i;
                    Local paramLocal = Jimple.v().newLocal(paramLocalName, paramType);
                    body.getLocals().add(paramLocal);
                    
                    // Create appropriate default values
                    if (paramType instanceof RefType) {
                        body.getUnits().add(Jimple.v().newAssignStmt(
                            paramLocal, soot.jimple.NullConstant.v()));
                    } else if (paramType instanceof IntType) {
                        body.getUnits().add(Jimple.v().newAssignStmt(
                            paramLocal, soot.jimple.IntConstant.v(0)));
                    }
                    paramLocals.add(paramLocal);
                }
                
                // Invoke test method
                body.getUnits().add(Jimple.v().newInvokeStmt(
                    Jimple.v().newVirtualInvokeExpr(instanceLocal, testMethod.makeRef(), paramLocals)));
                
                // Return
                body.getUnits().add(Jimple.v().newReturnVoidStmt());
                
                // Add wrapper as entry point
                _directEntryPoints.add(wrapperMethod);
                
                System.err.println("DIRECT ENTRYPOINTS: Created wrapper entry point: " + wrapperMethod.getSignature());
            }
            
        } catch (Exception e) {
            System.err.println("DIRECT ENTRYPOINTS: Failed to create test method wrappers: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Get all direct entry points
     */
    public Set<MethodOrMethodContext> getDirectEntryPoints() {
        return Collections.unmodifiableSet(_directEntryPoints);
    }
    
    /**
     * Add direct entry points to existing entry point set
     */
    public void addToEntryPoints(Set<MethodOrMethodContext> entryPoints) {
        int originalSize = entryPoints.size();
        entryPoints.addAll(_directEntryPoints);
        
        System.err.println("DIRECT ENTRYPOINTS: Added " + (_directEntryPoints.size()) + 
                          " direct entry points, total now: " + entryPoints.size() + 
                          " (was: " + originalSize + ")");
    }
}