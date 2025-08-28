package pathsent.target.callgraph;

import pathsent.Output;
import pathsent.target.ManifestAnalysis;
import pathsent.target.methods.IntentMethods;
import pathsent.target.icc.IntentAnalysisHelper;
import pathsent.target.icc.ComponentSummaryTable;
import pathsent.target.icc.ICCCallerInfo;

import soot.*;
import soot.jimple.ClassConstant;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.StringConstant;
import pathsent.target.callgraph.CallGraphPatchingTag;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.LocalDefs;
import soot.toolkits.scalar.LocalUses;
import soot.toolkits.scalar.UnitValueBoxPair;

import java.util.*;

abstract class IntentBasedCallGraphPatcher extends CallGraphPatcher {
    protected static final SootClass _contextClass = Scene.v().getSootClass(
            "android.content.Context");

    // Note: The manifest analysis will be used when we add support for identifying the intent
    // target via the action flag.
    protected final ManifestAnalysis _manifestAnalysis;

    protected IntentBasedCallGraphPatcher(CallGraphPatchingTag.Kind kind, SootClass patchClass,
            ManifestAnalysis manifestAnalysis) {
        super(kind, patchClass);
        _manifestAnalysis = manifestAnalysis;
    }

    protected List<SootClass> findTargetClassesFromIntent(final Body body, UnitGraph cfg,
            LocalDefs localDefs, LocalUses localUses, Stmt invokeStmt, Value intentValue) {
        System.err.println("PATHSENT-ICC: Finding target classes from Intent: " + intentValue);
        if (!(intentValue instanceof Local)) {
            System.err.println("PATHSENT-ICC: Intent value is not a Local, returning null");
            return null;
        }

        //InvokeExpr invoke = invokeStmt.getInvokeExpr();
        final List<SootClass> targetClasses = new ArrayList<SootClass>();
        Local intentLocal = (Local)intentValue;

        processDefUseForBuilderPattern(
                body, localDefs, localUses, invokeStmt, intentLocal, stmt -> {
                if (!stmt.containsInvokeExpr()) {
                    return;
                }

                InvokeExpr invoke = stmt.getInvokeExpr();
                SootMethod invokedMethod = invoke.getMethod();

                if (!IntentMethods.isIntentTargetMethod(invokedMethod)) {
                    return;
                }

                int targetIndex = IntentMethods.getIntentTargetParameterIndex(invokedMethod);
                Value targetValue = invoke.getArg(targetIndex);

                switch (IntentMethods.getIntentTargetType(invokedMethod)) {
                    case CLASS:
                        List<SootClass> classTargets = findClassesFromIntentClass(
                                localDefs, localUses, stmt, targetValue);
                        System.err.println("PATHSENT-ICC: Found CLASS targets: " + classTargets);
                        targetClasses.addAll(classTargets);
                        break;
                    case STRING:
                        List<SootClass> stringTargets = findClassesFromIntentClassName(
                                localDefs, localUses, stmt, targetValue);
                        System.err.println("PATHSENT-ICC: Found STRING targets: " + stringTargets);
                        targetClasses.addAll(stringTargets);
                        break;
                    case COMPONENT_NAME:
                        List<SootClass> compTargets = findClassesFromIntentComponentName(
                                localDefs, localUses, stmt, targetValue);
                        System.err.println("PATHSENT-ICC: Found COMPONENT_NAME targets: " + compTargets);
                        targetClasses.addAll(compTargets);
                        break;
                    default:
                        break;
                }
            }
        );

        return targetClasses;
    }

    private List<SootClass> findClassesFromIntentClass(LocalDefs localDefs,
            LocalUses localUses, Stmt setClassInvokeStmt, Value classValue) {
        if (classValue instanceof ClassConstant) {
            ClassConstant classConstant = (ClassConstant)classValue;
            String className = classConstant.getValue().replace('/', '.');
            if (Scene.v().containsClass(className)) {
                return Collections.singletonList(Scene.v().getSootClass(className));
            }
        }

        return Collections.emptyList();
    }

    private List<SootClass> findClassesFromIntentClassName(LocalDefs localDefs,
            LocalUses localUses, Stmt setClassNameInvokeStmt, Value classNameValue) {
        if (classNameValue instanceof StringConstant) {
            String className = classNameValue.toString();
            if (Scene.v().containsClass(className)) {
                return Collections.singletonList(Scene.v().getSootClass(className));
            }
        }

        return Collections.emptyList();
    }

    private List<SootClass> findClassesFromIntentComponentName(LocalDefs localDefs,
            LocalUses localUses, Stmt setComponentInvokeStmt, Value componentValue) {
        if (componentValue == null || !(componentValue instanceof Local)) {
            return Collections.emptyList();
        }

        final List<SootClass> targetClasses = new ArrayList<SootClass>();
        Local componentLocal = (Local)componentValue;

        for (Unit defUnit : localDefs.getDefsOfAt(componentLocal, setComponentInvokeStmt)) {
            for (UnitValueBoxPair useUnitValue : localUses.getUsesOf(defUnit)) {
                Stmt useStmt = (Stmt)useUnitValue.getUnit();
                if (!useStmt.containsInvokeExpr()) {
                    continue;
                }

                InvokeExpr useInvoke = useStmt.getInvokeExpr();
                SootMethod invokedMethod = useInvoke.getMethod();

                if (!IntentMethods.isIntentTargetMethod(invokedMethod)) {
                    continue;
                }

                int targetIndex = IntentMethods.getIntentTargetParameterIndex(invokedMethod);
                Value targetValue = useInvoke.getArg(targetIndex);

                switch (IntentMethods.getIntentTargetType(invokedMethod)) {
                    case CLASS:
                        targetClasses.addAll(findClassesFromIntentClass(
                                localDefs, localUses, useStmt, targetValue));
                        break;
                    case STRING:
                        targetClasses.addAll(findClassesFromIntentClassName(
                                localDefs, localUses, useStmt, targetValue));
                        break;
                    default:
                        break;
                }
            }
        }

        return targetClasses;
    }

    /**
     * Extract Intent content using enhanced analysis
     */
    protected Set<IntentAnalysisHelper.IntentContent> extractIntentContents(Value intentValue, Body body) {
        return IntentAnalysisHelper.extractIntentContents(intentValue, body);
    }
    
    /**
     * Create ICC caller info for component summary analysis
     */
    protected ICCCallerInfo.IntentCaller createIntentCaller(SootClass callerComponent, SootMethod callerMethod, 
            Stmt callSite, IntentAnalysisHelper.IntentContent intentContent, String iccMethodName) {
        return new ICCCallerInfo.IntentCaller(callerComponent, callerMethod, callSite, intentContent, iccMethodName);
    }
    
    /**
     * Enhanced target class finding using Intent content analysis
     */
    protected List<SootClass> findTargetClassesFromIntentContent(IntentAnalysisHelper.IntentContent intentContent) {
        List<SootClass> targetClasses = new ArrayList<>();
        
        if (intentContent.isExplicit() && intentContent.isPrecise()) {
            // Explicit precise intent - use component names
            for (String componentName : intentContent.getComponentNames()) {
                if (Scene.v().containsClass(componentName)) {
                    targetClasses.add(Scene.v().getSootClass(componentName));
                }
            }
        } else if (intentContent.isExplicit() && !intentContent.isPrecise()) {
            // Explicit imprecise intent - could target any component of appropriate type
            // This is handled in specific patchers based on context (Activity vs Service vs Receiver)
        } else if (!intentContent.isExplicit()) {
            // Implicit intent - match against manifest intent filters
            targetClasses.addAll(findTargetClassesFromImplicitIntent(intentContent));
        }
        
        return targetClasses;
    }
    
    /**
     * Find target classes for implicit intents using manifest analysis
     */
    private List<SootClass> findTargetClassesFromImplicitIntent(IntentAnalysisHelper.IntentContent intentContent) {
        List<SootClass> targetClasses = new ArrayList<>();
        
        // Use manifest analysis to find components with matching intent filters
        // This is a simplified implementation - full implementation would require
        // parsing AndroidManifest.xml intent filters and matching them
        
        for (String action : intentContent.getActions()) {
            // Find components that handle this action
            List<String> handlers = findComponentsForAction(action);
            for (String handler : handlers) {
                if (Scene.v().containsClass(handler)) {
                    targetClasses.add(Scene.v().getSootClass(handler));
                }
            }
        }
        
        return targetClasses;
    }
    
    /**
     * Find components that can handle the given action
     * This uses the manifest analysis to look up intent filters
     */
    private List<String> findComponentsForAction(String action) {
        List<String> components = new ArrayList<>();
        
        // Check all manifest components for this action
        // This is a placeholder - real implementation would parse intent filters
        if ("android.intent.action.MAIN".equals(action)) {
            components.addAll(_manifestAnalysis.getAllActivityNames());
        } else if ("android.intent.action.BOOT_COMPLETED".equals(action)) {
            components.addAll(_manifestAnalysis.getAllReceiverNames());
        }
        // Add more action mappings as needed
        
        return components;
    }

    //private List<SootClass> findClassesFromIntentAction(LocalDefs localDefs,
    //        LocalUses localUses, Stmt setActionInvokeStmt, Value actionValue) {
    //    return Collections.emptyList();
    //}
}
