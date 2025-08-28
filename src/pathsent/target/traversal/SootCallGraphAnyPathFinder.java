package pathsent.target.traversal;

import pathsent.Output;

import soot.MethodOrMethodContext;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.callgraph.EdgePredicate;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Stack;

// Performs a depth-first search over soot's call-graph by its following edges.  An edge
// predicate object should be passed in that indicates whether a particular target
// edge/node is interesting and its path should be returned.

// This is a stack-based search and should only be used for an any-path traversal of the
// call-graph.

public class SootCallGraphAnyPathFinder {
    protected final CallGraph _graph;
    private final Iterator<Edge> _entryPoints;

    protected final Stack<Edge> _currentPath = new Stack<Edge>();
    private final EdgePredicate _edgePredicate;

    protected final Map<MethodOrMethodContext, Iterator<Edge>> _pendingEdges =
            new LinkedHashMap<MethodOrMethodContext, Iterator<Edge>>(1000);
    
    // Limits to prevent infinite loops
    private static final int MAX_ITERATIONS_PER_ENTRY_POINT = 1000;
    private static final int MAX_PATH_DEPTH = 50;
    private static final long TIMEOUT_PER_ENTRY_POINT_MS = 30000; // 30 seconds
    
    private long _entryPointStartTime;
    private int _currentEntryPointIterations;

    public SootCallGraphAnyPathFinder(CallGraph graph, MethodOrMethodContext entryMethod,
            EdgePredicate edgePredicate) {
        _graph = graph;
        _entryPoints = graph.edgesInto(entryMethod);
        _edgePredicate = edgePredicate;

        initializeTraversal();
    }

    public SootCallGraphAnyPathFinder(CallGraph graph,
            Iterator<MethodOrMethodContext> entryMethods, EdgePredicate edgePredicate) {
        _graph = graph;

        ArrayList<Edge> entryEdges = new ArrayList<Edge>();
        while (entryMethods.hasNext()) {
            Iterator<Edge> edgeIter = graph.edgesInto(entryMethods.next());
            while (edgeIter.hasNext()) {
                entryEdges.add(edgeIter.next());
            }
        }
        _entryPoints = entryEdges.iterator();
        _edgePredicate = edgePredicate;

        initializeTraversal();
    }

    private void initializeTraversal() {
        if (_entryPoints != null && _entryPoints.hasNext()) {
            Edge entryEdge = _entryPoints.next();
            System.err.println("PATH-FINDER: Starting traversal from " + entryEdge.toString());
            Output.debug("Starting traversal from " + entryEdge.toString());

            // Reset counters for new entry point
            _entryPointStartTime = System.currentTimeMillis();
            _currentEntryPointIterations = 0;

            _currentPath.push(entryEdge);
            _pendingEdges.put(entryEdge.getTgt(), computeChildren(entryEdge));
            
            System.err.println("PATH-FINDER: Initialized with entry point: " + 
                              entryEdge.getTgt().method().getSignature() + 
                              ", children: " + getChildrenCount(entryEdge));
        } else {
            System.err.println("PATH-FINDER: WARNING - No entry points available for traversal");
        }
    }

    public List<Edge> next() {
        while (!_currentPath.empty()) {
            _currentEntryPointIterations++;
            long currentTime = System.currentTimeMillis();
            long elapsed = currentTime - _entryPointStartTime;
            
            // Check timeout per entry point
            if (elapsed > TIMEOUT_PER_ENTRY_POINT_MS) {
                System.err.println("PATH-FINDER: WARNING - Entry point timeout (" + 
                                  (TIMEOUT_PER_ENTRY_POINT_MS/1000) + "s) reached after " + 
                                  _currentEntryPointIterations + " iterations. Skipping to next entry point.");
                moveToNextEntryPoint();
                continue;
            }
            
            // Check iteration limit per entry point
            if (_currentEntryPointIterations > MAX_ITERATIONS_PER_ENTRY_POINT) {
                System.err.println("PATH-FINDER: WARNING - Entry point iteration limit (" + 
                                  MAX_ITERATIONS_PER_ENTRY_POINT + ") reached. Skipping to next entry point.");
                moveToNextEntryPoint();
                continue;
            }
            
            // Check path depth limit
            if (_currentPath.size() > MAX_PATH_DEPTH) {
                System.err.println("PATH-FINDER: WARNING - Path depth limit (" + MAX_PATH_DEPTH + 
                                  ") reached. Backtracking.");
                _currentPath.pop(); // Force backtrack
                continue;
            }
            
            Edge currentEdge = _currentPath.peek();

            // Log current path exploration state
            if (_currentEntryPointIterations % 100 == 0) {
                System.err.println("PATH-FINDER: Entry point iteration " + _currentEntryPointIterations + 
                                  ", path depth: " + _currentPath.size() + 
                                  ", pending nodes: " + _pendingEdges.size() + 
                                  ", elapsed: " + (elapsed/1000) + "s" +
                                  ", current: " + currentEdge.getTgt().method().getSignature());
            }

            if (_edgePredicate.want(currentEdge)) {
                List<Edge> path = currentPath();
                System.err.println("PATH-FINDER: Found target path after " + _currentEntryPointIterations + 
                                  " iterations (" + (elapsed/1000) + "s), path length: " + path.size() + 
                                  ", target: " + currentEdge.getTgt().method().getSignature());
                continueTraversal();
                return path;
            }

            continueTraversal();
        }

        System.err.println("PATH-FINDER: Finished all entry points. Total iterations: " + 
                          _currentEntryPointIterations + ", time: " + 
                          ((System.currentTimeMillis() - _entryPointStartTime)/1000) + "s");
        return null;
    }

    protected List<Edge> currentPath() {
        ArrayList<Edge> result = new ArrayList<Edge>();
        _currentPath.iterator().forEachRemaining(e -> { result.add(e); });
        return result;
    }

    private void continueTraversal() {
        while (!_currentPath.empty()) {
            Edge currentEdge = _currentPath.peek();
            Iterator<Edge> children = _pendingEdges.get(currentEdge.getTgt());

            while (children.hasNext()) {
                Edge child = children.next();

                if (!_pendingEdges.containsKey(child.getTgt())) {
                    // This is a new node we have not yet explored.
                    _currentPath.push(child);
                    Iterator<Edge> childChildren = computeChildren(child);
                    _pendingEdges.put(child.getTgt(), childChildren);
                    
                    // Log new node exploration
                    System.err.println("PATH-FINDER: Exploring new node: " + 
                                      child.getTgt().method().getSignature() + 
                                      ", depth: " + _currentPath.size() + 
                                      ", children: " + getChildrenCount(child));
                    return;
                }
            }

            // We have no more unvisited edges for the current node, so move backwards
            Edge poppedEdge = _currentPath.pop();
            System.err.println("PATH-FINDER: Backtracking from: " + 
                              poppedEdge.getTgt().method().getSignature() + 
                              ", new depth: " + _currentPath.size());
        }

        // We're done with the paths stemming from the current entry-point.  Move on to the
        // next one.
        moveToNextEntryPoint();
        return;
    }
    
    /**
     * Move to the next entry point, resetting counters and state
     */
    private void moveToNextEntryPoint() {
        // Clear current path and prepare for next entry point
        _currentPath.clear();
        
        System.err.println("PATH-FINDER: Finished current entry point after " + 
                          _currentEntryPointIterations + " iterations in " + 
                          ((System.currentTimeMillis() - _entryPointStartTime)/1000) + "s");
        System.err.println("PATH-FINDER: Checking for next entry point...");
        
        while (_entryPoints.hasNext()) {
            Edge nextEntryPoint = _entryPoints.next();

            if (!_pendingEdges.containsKey(nextEntryPoint.getTgt())) {
                // We have not yet visited this entry-point during our previous exploration.
                System.err.println("PATH-FINDER: Starting next entry point: " + 
                                  nextEntryPoint.getTgt().method().getSignature());
                
                // Reset counters for new entry point
                _entryPointStartTime = System.currentTimeMillis();
                _currentEntryPointIterations = 0;
                
                _currentPath.push(nextEntryPoint);
                _pendingEdges.put(nextEntryPoint.getTgt(), computeChildren(nextEntryPoint));
                return;
            } else {
                System.err.println("PATH-FINDER: Skipping already visited entry point: " + 
                                  nextEntryPoint.getTgt().method().getSignature());
            }
        }

        System.err.println("PATH-FINDER: No more entry points to explore");
    }

    protected Iterator<Edge> computeChildren(Edge edge) {
        // CallGraph.edgesOutOf() sometimes return non-sensical edges...
        List<Edge> result = new ArrayList<Edge>();

        Iterator<Edge> outEdgeIter = _graph.edgesOutOf(edge.getTgt());
        int totalEdges = 0;
        int validEdges = 0;
        
        while (outEdgeIter.hasNext()) {
            totalEdges++;
            Edge outEdge = outEdgeIter.next();

            if (outEdge.srcUnit() != null) {
                result.add(outEdge);
                validEdges++;
            }
        }

        System.err.println("PATH-FINDER: computeChildren for " + edge.getTgt().method().getSignature() + 
                          ": " + validEdges + "/" + totalEdges + " valid edges");

        return result.iterator();
    }
    
    /**
     * Helper method to count children for logging
     */
    private int getChildrenCount(Edge edge) {
        Iterator<Edge> outEdgeIter = _graph.edgesOutOf(edge.getTgt());
        int count = 0;
        
        while (outEdgeIter.hasNext()) {
            Edge outEdge = outEdgeIter.next();
            if (outEdge.srcUnit() != null) {
                count++;
            }
        }
        
        return count;
    }
}
