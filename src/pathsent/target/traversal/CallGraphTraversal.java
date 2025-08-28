package pathsent.target.traversal;

import pathsent.Output;
import pathsent.target.entrypoint.IEntryPointAnalysis;
import pathsent.target.event.CallPath;

import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.*;

import java.util.*;

/*
 * A class that gathers all necessary information from a single traversal of the call graph.
 * If a specific type of information needs to be gathered, implement a subclass of
 * CallGraphTraversalPlugin which specifies whether a Unit (i.e. instruction) is of interest
 * stores the resulting call path for that instruction.
 *
 * An aggregate edge predicate is used with the path finder to track which plugin has
 * expressed interest in a given instruction.
 */

public class CallGraphTraversal extends SceneTransformer {
    public static interface Plugin {
        // Process the given unit and return true if this unit should be targeted
        public boolean processUnit(SootMethod method, Unit unit);

        // Process the resulting targeted call path
        public void onTargetPath(CallPath path);
    }

    private final IEntryPointAnalysis _entryPointAnalysis;
    private final List<Plugin> _plugins = new ArrayList<Plugin>();

    public CallGraphTraversal(IEntryPointAnalysis entryPointAnalysis) {
        _entryPointAnalysis = entryPointAnalysis;
    }

    public void addPlugin(Plugin plugin) {
        _plugins.add(plugin);
    }

    @Override
    protected void internalTransform(String phaseName, Map<String, String> options) {
        Output.progress("Traversing the call graph");
        
        System.err.println("CALL-GRAPH-TRAVERSAL: ========== Starting Call Graph Traversal ==========");
        System.err.println("CALL-GRAPH-TRAVERSAL: Entry points: " + _entryPointAnalysis.getEntryPoints().size());
        System.err.println("CALL-GRAPH-TRAVERSAL: Registered plugins: " + _plugins.size());
        
        Output.debug("TRAVERSAL: Starting call graph traversal with " + _entryPointAnalysis.getEntryPoints().size() + " entry points");
        for (MethodOrMethodContext entryPoint : _entryPointAnalysis.getEntryPoints()) {
            System.err.println("CALL-GRAPH-TRAVERSAL: Entry Point: " + entryPoint.method().getSignature());
            Output.debug("  ENTRY POINT: " + entryPoint.method().getSignature());
            SootClass entryClass = entryPoint.method().getDeclaringClass();
            System.err.println("CALL-GRAPH-TRAVERSAL:   Class: " + entryClass.getName() + 
                              " (isApplicationClass=" + entryClass.isApplicationClass() + ")");
            Output.debug("    CLASS STATUS: " + entryClass.getName() + " isApplicationClass=" + entryClass.isApplicationClass());
            
            // Force mark as application class if it's our test app
            if (entryClass.getName().startsWith("com.test.pathsent_tester")) {
                entryClass.setApplicationClass();
                System.err.println("CALL-GRAPH-TRAVERSAL:   FORCED APPLICATION CLASS: " + entryClass.getName());
                Output.debug("    FORCED APPLICATION CLASS: " + entryClass.getName());
            }
        }

        System.err.println("CALL-GRAPH-TRAVERSAL: Creating edge predicate and path finder...");
        PluginBasedEdgePredicate edgePredicate = new PluginBasedEdgePredicate(_plugins);
        AndroidAnyPathFinder pathFinder = new AndroidAnyPathFinder(
                Scene.v().getCallGraph(), _entryPointAnalysis.getEntryPoints().iterator(),
                edgePredicate);

        int pathCount = 0;
        long startTime = System.currentTimeMillis();
        final long OVERALL_TIMEOUT_MS = 300000; // 5 minutes total timeout
        
        System.err.println("CALL-GRAPH-TRAVERSAL: Starting path discovery (timeout: " + 
                          (OVERALL_TIMEOUT_MS/1000) + " seconds)...");
        
        for (List<Edge> path = pathFinder.next(); 
             path != null && (System.currentTimeMillis() - startTime) < OVERALL_TIMEOUT_MS; 
             path = pathFinder.next()) {
            pathCount++;
            System.err.println("CALL-GRAPH-TRAVERSAL: ===== Found Path #" + pathCount + " =====");
            System.err.println("CALL-GRAPH-TRAVERSAL: Path length: " + path.size() + " edges");
            System.err.println("CALL-GRAPH-TRAVERSAL: Path from: " + 
                              path.get(0).getSrc().method().getSignature() + " to: " + 
                              path.get(path.size()-1).getTgt().method().getSignature());
            
            Output.debug("TRAVERSAL: Found path with " + path.size() + " edges:");
            for (int i = 0; i < path.size(); i++) {
                Edge edge = path.get(i);
                if (i < 3 || i >= path.size() - 3) { // Log first 3 and last 3 edges
                    System.err.println("CALL-GRAPH-TRAVERSAL:   Edge " + i + ": " + 
                                      edge.getSrc().method().getSignature() + " -> " + 
                                      edge.getTgt().method().getSignature());
                }
                Output.debug("  Edge " + i + ": " + edge.getSrc().method().getSignature() + " -> " + edge.getTgt().method().getSignature());
            }
            
            if (path.size() > 6) {
                System.err.println("CALL-GRAPH-TRAVERSAL:   ... (" + (path.size() - 6) + " edges omitted) ...");
            }
            
            for (Plugin plugin : _plugins) {
                for (Unit targetUnit : edgePredicate.getTargetUnitsForPlugin(plugin)) {
                    System.err.println("CALL-GRAPH-TRAVERSAL: Creating CallPath for plugin: " + 
                                      plugin.getClass().getSimpleName() + ", target unit: " + targetUnit);
                    Output.debug("TRAVERSAL: Creating CallPath for target unit: " + targetUnit);
                    CallPath newCallPath = new CallPath(path, targetUnit);
                    plugin.onTargetPath(newCallPath);
                }
            }
            
            // Progress tracking
            if (pathCount % 5 == 0) {
                long elapsed = System.currentTimeMillis() - startTime;
                System.err.println("CALL-GRAPH-TRAVERSAL: Progress: " + pathCount + " paths found in " + 
                                  (elapsed / 1000) + " seconds");
            }
        }
        
        long totalTime = System.currentTimeMillis() - startTime;
        boolean timedOut = totalTime >= OVERALL_TIMEOUT_MS;
        
        System.err.println("CALL-GRAPH-TRAVERSAL: ========== Traversal Complete ==========");
        System.err.println("CALL-GRAPH-TRAVERSAL: Total paths found: " + pathCount);
        System.err.println("CALL-GRAPH-TRAVERSAL: Total time: " + (totalTime / 1000) + " seconds");
        System.err.println("CALL-GRAPH-TRAVERSAL: Average time per path: " + 
                          (pathCount > 0 ? (totalTime / pathCount) + " ms" : "N/A"));
        
        if (timedOut) {
            System.err.println("CALL-GRAPH-TRAVERSAL: WARNING - Overall timeout reached. " +
                              "Analysis may be incomplete.");
        }
    }

    private class PluginBasedEdgePredicate implements EdgePredicate {
        private final Map<Plugin, List<Unit>> _pluginTargets =
                new HashMap<Plugin, List<Unit>>();

        public PluginBasedEdgePredicate(List<Plugin> plugins) {
            plugins.forEach(p -> { _pluginTargets.put(p, new ArrayList<Unit>()); });
        }

        @Override
        public boolean want(Edge e) {
            SootMethod tgtMethod = e.getTgt().method();
            if (!tgtMethod.hasActiveBody()) {
                return false;
            }

            clearPluginTargets();
            boolean isTarget = false;

            for (Unit unit : tgtMethod.getActiveBody().getUnits()) {
                for (Map.Entry<Plugin, List<Unit>> pluginEntry : _pluginTargets.entrySet()) {
                    if (pluginEntry.getKey().processUnit(tgtMethod, unit)) {
                        pluginEntry.getValue().add(unit);
                        isTarget = true;
                    }
                }
            }

            return isTarget;
        }

        public List<Unit> getTargetUnitsForPlugin(Plugin plugin) {
            return _pluginTargets.get(plugin);
        }

        private void clearPluginTargets() {
            _pluginTargets.forEach((p, t) -> { t.clear(); });
        }
    }
}
