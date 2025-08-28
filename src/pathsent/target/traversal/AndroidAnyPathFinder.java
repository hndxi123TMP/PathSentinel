package pathsent.target.traversal;

import soot.*;
import soot.jimple.toolkits.callgraph.*;

import java.util.*;

class AndroidAnyPathFinder extends SootCallGraphAnyPathFinder {
    public AndroidAnyPathFinder(CallGraph graph, MethodOrMethodContext entryMethod,
            EdgePredicate edgePredicate) {
        super(graph, entryMethod, edgePredicate);
    }

    public AndroidAnyPathFinder(CallGraph graph, Iterator<MethodOrMethodContext> entryMethods,
            EdgePredicate edgePredicate) {
        super(graph, entryMethods, edgePredicate);
        
        // Debug: AndroidAnyPathFinder created
        System.err.println("PATHFINDER: AndroidAnyPathFinder created");
    }

    @Override
    protected Iterator<Edge> computeChildren(Edge edge) {
        // Filter the traversal to only application classes, but allow java.io.* for file operations
        SootClass currentClass = edge.getTgt().method().getDeclaringClass();
        String className = currentClass.getName();
        
        System.err.println("PATHFINDER: computeChildren for edge to: " + edge.getTgt().method().getSignature());

        // Allow application classes and java.io.* classes (for file operation targets)
        if (currentClass.isApplicationClass() 
                || className.startsWith("java.io.")) {
            // Exclude android support libraries
            if (className.startsWith("android.support.v")) {
                System.err.println("  PATHFINDER: Excluding android.support class: " + className);
                return Collections.<Edge>emptyList().iterator();
            }
            System.err.println("  PATHFINDER: Allowing traversal of: " + className);
            return super.computeChildren(edge);
        }

        System.err.println("  PATHFINDER: Excluding non-application class: " + className);
        return Collections.<Edge>emptyList().iterator();
    }
}
