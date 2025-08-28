package pathsent.target.constraint;

import pathsent.Output;
import pathsent.target.event.CallPath;

import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.Edge;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.UnitGraph;

import java.util.*;

public class ConstraintAnalysis {
    // TODO Depending on the trade-off between memory vs CPU, we may want to cache instances of
    // the intraprocedural analysis and re-use them for cases with the same method +
    // paramterMap.

    protected final CallPath _callPath;
    protected final Set<SootMethod> _pathMethods;
    protected Predicate _constraints;
    protected final Set<HeapVariable> _heapDependencies = new HashSet<HeapVariable>();
    protected final List<StringParameterConstraint> _stringParameterConstraints = new ArrayList<>();
    protected final StringParameterAnalyzer _stringParameterAnalyzer = new StringParameterAnalyzer();

    public ConstraintAnalysis(CallPath callPath) {
        _callPath = callPath;

        _pathMethods = new HashSet<SootMethod>();
        _callPath.getNodes().forEach(m -> { _pathMethods.add(m.method()); });
    }

    public Predicate getConstraints() {
        extractConstraints();
        minimizeConstraints();

        return _constraints;
    }

    public List<HeapVariable> getHeapDependencies() {
        List<HeapVariable> result = new ArrayList<HeapVariable>();

        if (_constraints != null) {
            for (HeapVariable heapVariable : _heapDependencies) {
                if (_constraints.containsExpression(heapVariable.getExpression())) {
                    result.add(heapVariable);
                }
            }
        }

        return result;
    }

    public List<StringParameterConstraint> getStringParameterConstraints() {
        return new ArrayList<>(_stringParameterConstraints);
    }

    protected void minimizeConstraints() {
        _constraints = ConstraintMinimization.minimize(_constraints);
    }

    protected DataMap generateEntryPointParameterMap() {
        DataMap parameterMap = new DataMap();
        SootMethod entryPointMethod = _callPath.getNodes().get(0).method();
        
        Output.debug("CONSTRAINT: Generating parameter map for entry point: " + entryPointMethod.getSignature());

        // Handle "this"
        if (!entryPointMethod.isStatic()) {
            Local thisLocal = entryPointMethod.getActiveBody().getThisLocal();
            InputVariable thisVar = new InputVariable(_callPath, 0, entryPointMethod.getDeclaringClass().getType());
            parameterMap.LocalMap.put(thisLocal, new ExpressionSet(new VariableExpression(thisVar)));
            Output.debug("CONSTRAINT: Added 'this' parameter: " + thisLocal + " -> " + thisVar);
        }

        // Handle parameters
        for (int i = 0; i < entryPointMethod.getParameterCount(); i++) {
            Local paramLocal = entryPointMethod.getActiveBody().getParameterLocal(i);
            InputVariable inputVar = new InputVariable(_callPath, i + 1, entryPointMethod.getParameterType(i));
            parameterMap.LocalMap.put(paramLocal, new ExpressionSet(new VariableExpression(inputVar)));
            Output.debug("CONSTRAINT: Added parameter " + i + ": " + paramLocal + " -> " + inputVar);
        }

        Output.debug("CONSTRAINT: Generated parameter map with " + parameterMap.LocalMap.size() + " entries");
        return parameterMap;
    }

    protected void extractConstraints() {
        Output.debug("CONSTRAINT: Starting constraint extraction for path with " + _callPath.getEdges().size() + " edges");
        
        // Create initial parameter map
        DataMap parameterMap = generateEntryPointParameterMap();
        Output.debug("CONSTRAINT: Generated entry point parameter map: " + parameterMap);

        // Analyze constraints for each node
        for (Edge pathEdge : _callPath.getEdges()) {
            Output.debug("CONSTRAINT: Analyzing edge: " + pathEdge.getSrc().method().getSignature() + " -> " + pathEdge.getTgt().method().getSignature());
            parameterMap = extractConstraintsForPathEdge(pathEdge, parameterMap);
        }

        extractConstraintsForTargetUnit(_callPath.getTargetMethod(),
                _callPath.getTargetUnit(), parameterMap);
    }

    protected DataMap extractConstraintsForPathEdge(Edge edge, DataMap parameterMap) {
        Output.debug("ConstraintAnalysis processing edge: " + edge);

        MethodOrMethodContext node = edge.getSrc();
        MethodOrMethodContext nextNode = edge.getTgt();
        Stmt nodeTargetStmt = (Stmt)edge.srcUnit();

        UnitGraph cfg = new BriefUnitGraph(node.method().getActiveBody());
        IntraproceduralConstraintAnalysis intraAnalysis =
                new IntraproceduralConstraintAnalysis(cfg, parameterMap, _pathMethods);

        // Get data map and constraints at point where next method in path is invoked
        DataMap targetDataMap = intraAnalysis.getFlowBefore(nodeTargetStmt);

        _constraints = Predicate.combine(Predicate.Operator.AND,
                                         _constraints,
                                         targetDataMap.ControlFlowConstraint);

        // Update heap dependencies
        _heapDependencies.addAll(intraAnalysis.getHeapDependencies());

        // Determine variables used in invocation and construct parameter map for next path
        // method.
        DataMap nextParameterMap = new DataMap();
        nextParameterMap.HeapMap.putAll(targetDataMap.HeapMap);

        // Note: Target unit may containing a StaticFieldRef if <clinit> is in the path.  Since
        // <clinit> doesn't take parameters, we don't need to add anything to the LocalMap
        if (nodeTargetStmt.containsInvokeExpr()) {
            InvokeExpr targetInvokeExpr = nodeTargetStmt.getInvokeExpr();
            SootMethod nextMethod = nextNode.method();

            // Offset parameters if we have an instance invocation to a static method (likely
            // a special case for reflection or other type of call graph patching.
            int argOffset =
                    (targetInvokeExpr instanceof InstanceInvokeExpr) && nextMethod.isStatic()
                    ? 1 : 0;

            // Handle base for instance invokes
            //if (!nextMethod.isStatic() && targetInvokeExpr instanceof InstanceInvokeExpr) {
            if (targetInvokeExpr instanceof InstanceInvokeExpr
                    && (!nextMethod.isStatic() || nextMethod.getParameterCount() > 0)) {
                InstanceInvokeExpr instanceExpr = (InstanceInvokeExpr)targetInvokeExpr;
                Value base = instanceExpr.getBase();
                Local nextNodeBase = (argOffset == 0)
                        ? nextMethod.getActiveBody().getThisLocal()
                        : nextMethod.getActiveBody().getParameterLocal(0);

                if (base instanceof Local) {
                    Local baseLocal = (Local)base;
                    if (targetDataMap.LocalMap.containsKey(baseLocal)) {
                        nextParameterMap.LocalMap.put(
                                nextNodeBase, targetDataMap.LocalMap.get(baseLocal));
                    }
                } else if (base instanceof Constant) {
                    Constant baseConstant = (Constant)base;
                    ConstantVariable constantVar =
                            ConstantVariable.generateFromSootConstant(baseConstant);
                    ExpressionSet constantExprSet = new ExpressionSet(
                            new VariableExpression(constantVar));
                    nextParameterMap.LocalMap.put(nextNodeBase, constantExprSet);
                }
            }

            // Handle arguments
            // TODO handle reflected method invocations
            for (int argIndex = 0;
                    argIndex < targetInvokeExpr.getArgCount()
                        && argIndex + argOffset < nextMethod.getParameterCount();
                    argIndex++) {

                Value arg = targetInvokeExpr.getArg(argIndex);
                Local nextNodeArg =
                        nextMethod.getActiveBody().getParameterLocal(argIndex + argOffset);

                if (arg instanceof Local) {
                    Local argLocal = (Local)arg;
                    if (targetDataMap.LocalMap.containsKey(argLocal)) {
                        nextParameterMap.LocalMap.put(
                                nextNodeArg, targetDataMap.LocalMap.get(argLocal));
                    }
                } else if (arg instanceof Constant) {
                    Constant argConstant = (Constant)arg;
                    ConstantVariable constantVar =
                            ConstantVariable.generateFromSootConstant(argConstant);
                    ExpressionSet constantExprSet = new ExpressionSet(
                            new VariableExpression(constantVar));
                    nextParameterMap.LocalMap.put(nextNodeArg, constantExprSet);
                }
            }
        }

        return nextParameterMap;
    }

    protected void extractConstraintsForTargetUnit(SootMethod targetMethod, Unit targetUnit,
            DataMap parameterMap) {
        Output.debug("CONSTRAINT: Extracting constraints for target unit in method: " + targetMethod.getSignature());
        Output.debug("CONSTRAINT: Target unit: " + targetUnit);
        
        UnitGraph cfg = new BriefUnitGraph(targetMethod.getActiveBody());
        IntraproceduralConstraintAnalysis intraAnalysis =
                new IntraproceduralConstraintAnalysis(cfg, parameterMap, _pathMethods);

        // Get data map and constraints at unit
        DataMap targetDataMap = intraAnalysis.getFlowBefore(targetUnit);
        Output.debug("CONSTRAINT: Target data map control flow constraint: " + 
                    (targetDataMap.ControlFlowConstraint != null ? targetDataMap.ControlFlowConstraint.toString() : "null"));
        Output.debug("CONSTRAINT: Target data map has " + targetDataMap.LocalMap.size() + " local mappings:");
        targetDataMap.LocalMap.forEach((local, exprSet) -> {
            Output.debug("  LOCAL: " + local + " -> " + exprSet);
        });
        
        _constraints = Predicate.combine(Predicate.Operator.AND,
                                         _constraints,
                                         targetDataMap.ControlFlowConstraint);
        
        // Extract string parameter constraints if target unit is a method invocation
        if (targetUnit instanceof Stmt && ((Stmt)targetUnit).containsInvokeExpr()) {
            InvokeExpr invokeExpr = ((Stmt)targetUnit).getInvokeExpr();
            Output.debug("STRING_PARAM: Analyzing target method invocation: " + invokeExpr.getMethod().getSignature());
            
            List<StringParameterConstraint> stringConstraints = 
                _stringParameterAnalyzer.analyzeStringParameters(invokeExpr, targetDataMap);
            
            _stringParameterConstraints.addAll(stringConstraints);
            
            Output.debug("STRING_PARAM: Found " + stringConstraints.size() + " string parameter constraints");
            for (StringParameterConstraint constraint : stringConstraints) {
                Output.debug("STRING_PARAM: " + constraint.toString());
            }
        }
        
        Output.debug("CONSTRAINT: Combined constraints after target unit: " + 
                    (_constraints != null ? _constraints.toString() : "null"));

        // Update heap dependencies
        _heapDependencies.addAll(intraAnalysis.getHeapDependencies());

        // Process target unit/instruction (used for certain types of call paths/dependences)
        DataMap postTargetDataMap = ((Stmt)targetUnit).fallsThrough()
                ? intraAnalysis.getFallFlowAfter(targetUnit) : targetDataMap;
        processTargetUnit(_callPath.getTargetUnit(), postTargetDataMap);
    }

    // TODO: Implement data flow constraint generation
    // protected void generateDataFlowConstraints(Unit targetUnit, DataMap dataMap) {
    // }

    protected void processTargetUnit(Unit targetUnit, DataMap dataMap) {
        // Subclasses handling different types of call paths should override this

        // Debugging
        //dataMap.LocalMap.forEach(
        //        (x,y) -> { Output.debug("target local map: " + x + " -> " + y); });
        //dataMap.HeapMap.forEach(
        //        (x,y) -> { Output.debug("target heap map: " + x + " -> " + y); });
    }
}
