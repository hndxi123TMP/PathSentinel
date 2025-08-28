package pathsent.target.callgraph;

import pathsent.Output;
import pathsent.target.ManifestAnalysis;

import soot.*;
import soot.jimple.*;
import pathsent.target.callgraph.CallGraphPatchingTag;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.LocalDefs;
import soot.toolkits.scalar.LocalUses;
import soot.util.Chain;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

class ContentProviderPatcher extends CallGraphPatcher {
    private static final SootClass _contentResolverClass = Scene.v().getSootClass(
            "android.content.ContentResolver");
    
    // ContentResolver method signatures
    private static final String _queryMethodSignature = 
            "android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)";
    private static final String _insertMethodSignature = 
            "android.net.Uri insert(android.net.Uri,android.content.ContentValues)";
    private static final String _updateMethodSignature = 
            "int update(android.net.Uri,android.content.ContentValues,java.lang.String,java.lang.String[])";
    private static final String _deleteMethodSignature = 
            "int delete(android.net.Uri,java.lang.String,java.lang.String[])";
    private static final String _getTypeMethodSignature = 
            "java.lang.String getType(android.net.Uri)";
    private static final String _openFileMethodSignature = 
            "android.os.ParcelFileDescriptor openFileDescriptor(android.net.Uri,java.lang.String)";
    private static final String _openAssetFileMethodSignature = 
            "android.content.res.AssetFileDescriptor openAssetFileDescriptor(android.net.Uri,java.lang.String)";
    
    private final ManifestAnalysis _manifestAnalysis;

    public ContentProviderPatcher(SootClass patchClass, ManifestAnalysis manifestAnalysis) {
        super(CallGraphPatchingTag.Kind.Intent, patchClass); // Using Intent kind as ContentProvider not in enum
        _manifestAnalysis = manifestAnalysis;
    }

    @Override
    public boolean shouldPatch(final Body body, Stmt invokeStmt) {
        SootMethod invokedMethod = invokeStmt.getInvokeExpr().getMethod();
        
        // Check if the method is called on ContentResolver
        if (!_cha.isClassSuperclassOfIncluding(_contentResolverClass,
                invokedMethod.getDeclaringClass())) {
            return false;
        }

        String methodSig = invokedMethod.getSubSignature();
        return methodSig.equals(_queryMethodSignature) ||
               methodSig.equals(_insertMethodSignature) ||
               methodSig.equals(_updateMethodSignature) ||
               methodSig.equals(_deleteMethodSignature) ||
               methodSig.equals(_getTypeMethodSignature) ||
               methodSig.equals(_openFileMethodSignature) ||
               methodSig.equals(_openAssetFileMethodSignature);
    }

    @Override
    public void patch(final Body body, UnitGraph cfg, LocalDefs localDefs,
            LocalUses localUses, Stmt invokeStmt) {
        InvokeExpr invoke = invokeStmt.getInvokeExpr();
        String methodName = invoke.getMethod().getName();
        
        System.err.println("PATHSENT-PROVIDER: Patching ContentResolver." + methodName + ": " + invoke);
        
        // Get the URI argument (first parameter for all ContentResolver methods)
        Value uriArg = invoke.getArg(0);
        
        // Find target providers based on URI authority
        List<SootClass> targetProviders = findTargetProvidersFromUri(
                body, cfg, localDefs, localUses, invokeStmt, uriArg);
        
        if (targetProviders != null && !targetProviders.isEmpty()) {
            for (SootClass providerClass : targetProviders) {
                createProviderBridgeMethod(providerClass, methodName, invoke);
                System.err.println("PATHSENT-PROVIDER: Created " + methodName + " bridge for: " + providerClass.getName());
            }
        } else {
            // If we can't resolve specific providers, create bridges for all manifest providers
            System.err.println("PATHSENT-PROVIDER: Could not resolve target providers, adding all manifest providers");
            for (String providerName : _manifestAnalysis.getAllProviderNames()) {
                if (Scene.v().containsClass(providerName)) {
                    SootClass providerClass = Scene.v().getSootClass(providerName);
                    createProviderBridgeMethod(providerClass, methodName, invoke);
                }
            }
        }
    }
    
    private List<SootClass> findTargetProvidersFromUri(final Body body, UnitGraph cfg,
            LocalDefs localDefs, LocalUses localUses, Stmt invokeStmt, Value uriValue) {
        
        List<SootClass> providerClasses = new ArrayList<>();
        
        // Try to extract URI authority from the Uri value
        String authority = extractUriAuthority(body, localDefs, localUses, invokeStmt, uriValue);
        
        if (authority != null) {
            // Find provider that matches this authority
            for (String providerName : _manifestAnalysis.getAllProviderNames()) {
                if (Scene.v().containsClass(providerName)) {
                    SootClass providerClass = Scene.v().getSootClass(providerName);
                    if (providerMatchesAuthority(providerClass, authority)) {
                        providerClasses.add(providerClass);
                    }
                }
            }
        }
        
        return providerClasses.isEmpty() ? null : providerClasses;
    }
    
    private String extractUriAuthority(final Body body, LocalDefs localDefs, 
            LocalUses localUses, Stmt invokeStmt, Value uriValue) {
        // TODO: Implement URI authority extraction from Uri.parse() calls
        // This is complex as it requires analyzing string constants and Uri construction
        System.err.println("PATHSENT-PROVIDER: URI authority extraction not fully implemented for: " + uriValue);
        return null;
    }
    
    private boolean providerMatchesAuthority(SootClass providerClass, String authority) {
        // Check if provider's manifest authority matches the extracted authority
        Set<String> authorities = _manifestAnalysis.getProviderAuthorities();
        return authorities.contains(authority);
    }
    
    private void createProviderBridgeMethod(SootClass providerClass, String operationType, InvokeExpr originalInvoke) {
        String bridgeMethodName = "bridge_" + providerClass.getName().replace(".", "_") + "_" + operationType;
        
        if (_patchClass.declaresMethodByName(bridgeMethodName)) {
            // Bridge already exists
            return;
        }
        
        // Create bridge method with same signature as the ContentResolver method
        SootMethod originalMethod = originalInvoke.getMethod();
        List<Type> paramTypes = new ArrayList<>(originalMethod.getParameterTypes());
        Type returnType = originalMethod.getReturnType();
        
        SootMethod bridgeMethod = Scene.v().makeSootMethod(bridgeMethodName, paramTypes, returnType);
        _patchClass.addMethod(bridgeMethod);
        
        // Create method body
        JimpleBody body = Jimple.v().newBody(bridgeMethod);
        bridgeMethod.setActiveBody(body);
        
        // Create locals
        Local providerLocal = Jimple.v().newLocal("provider", providerClass.getType());
        body.getLocals().add(providerLocal);
        
        // Create parameter locals
        List<Local> paramLocals = new ArrayList<>();
        for (int i = 0; i < paramTypes.size(); i++) {
            Local paramLocal = Jimple.v().newLocal("param" + i, paramTypes.get(i));
            body.getLocals().add(paramLocal);
            paramLocals.add(paramLocal);
            
            // Add parameter identity statement
            body.getUnits().add(Jimple.v().newIdentityStmt(paramLocal, 
                    Jimple.v().newParameterRef(paramTypes.get(i), i)));
        }
        
        // Create provider instance
        body.getUnits().add(Jimple.v().newAssignStmt(providerLocal, 
                Jimple.v().newNewExpr(providerClass.getType())));
        
        // Call provider constructor
        SootMethod constructor = providerClass.getMethodUnsafe("void <init>()");
        if (constructor != null) {
            body.getUnits().add(Jimple.v().newInvokeStmt(
                    Jimple.v().newSpecialInvokeExpr(providerLocal, constructor.makeRef())));
        }
        
        // Find and call the corresponding provider method
        SootMethod providerMethod = findProviderMethod(providerClass, operationType, paramTypes);
        if (providerMethod != null) {
            // Create method call
            InvokeExpr providerInvoke = Jimple.v().newVirtualInvokeExpr(providerLocal, 
                    providerMethod.makeRef(), paramLocals);
            
            if (returnType instanceof VoidType) {
                body.getUnits().add(Jimple.v().newInvokeStmt(providerInvoke));
                body.getUnits().add(Jimple.v().newReturnVoidStmt());
            } else {
                Local returnLocal = Jimple.v().newLocal("returnValue", returnType);
                body.getLocals().add(returnLocal);
                
                body.getUnits().add(Jimple.v().newAssignStmt(returnLocal, providerInvoke));
                body.getUnits().add(Jimple.v().newReturnStmt(returnLocal));
            }
        } else {
            // If we can't find the method, just return null/void
            if (returnType instanceof VoidType) {
                body.getUnits().add(Jimple.v().newReturnVoidStmt());
            } else if (returnType instanceof RefType) {
                body.getUnits().add(Jimple.v().newReturnStmt(NullConstant.v()));
            } else {
                // For primitive types, return 0
                body.getUnits().add(Jimple.v().newReturnStmt(IntConstant.v(0)));
            }
        }
        
        System.err.println("PATHSENT-PROVIDER: Created bridge method: " + bridgeMethod.getSignature());
    }
    
    private SootMethod findProviderMethod(SootClass providerClass, String operationType, List<Type> paramTypes) {
        // Map ContentResolver method names to ContentProvider method names
        String providerMethodSig = null;
        
        switch (operationType) {
            case "query":
                providerMethodSig = "android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)";
                break;
            case "insert":
                providerMethodSig = "android.net.Uri insert(android.net.Uri,android.content.ContentValues)";
                break;
            case "update":
                providerMethodSig = "int update(android.net.Uri,android.content.ContentValues,java.lang.String,java.lang.String[])";
                break;
            case "delete":
                providerMethodSig = "int delete(android.net.Uri,java.lang.String,java.lang.String[])";
                break;
            case "getType":
                providerMethodSig = "java.lang.String getType(android.net.Uri)";
                break;
            case "openFileDescriptor":
                providerMethodSig = "android.os.ParcelFileDescriptor openFile(android.net.Uri,java.lang.String)";
                break;
            case "openAssetFileDescriptor":
                providerMethodSig = "android.content.res.AssetFileDescriptor openAssetFile(android.net.Uri,java.lang.String)";
                break;
        }
        
        if (providerMethodSig != null) {
            return providerClass.getMethodUnsafe(providerMethodSig);
        }
        
        return null;
    }
}