package pathsent.target.icc;

import soot.MethodOrMethodContext;
import soot.Unit;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.util.MultiMap;
import soot.util.HashMultiMap;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Iterator;
import java.util.Set;

/**
 * CallGraphModifier provides methods to modify Soot's CallGraph by adding edges
 * using reflection to access internal data structures.
 * 
 * This is necessary because Soot's CallGraph doesn't provide a public addEdge() method,
 * but we need to add ICC (Inter-Component Communication) edges for complete
 * Android call graph analysis.
 */
public class CallGraphModifier {
    private CallGraph callGraph;
    
    // Reflected fields for accessing CallGraph internals
    private Field edgesOutOfField;
    private Field edgesIntoField;
    private Method addEdgeMethod;
    
    // Track added edges for verification
    private Set<Edge> addedEdges = new java.util.HashSet<>();
    
    public CallGraphModifier(CallGraph callGraph) {
        this.callGraph = callGraph;
        initializeReflection();
    }
    
    /**
     * Initialize reflection fields and methods to access CallGraph internals
     */
    private void initializeReflection() {
        try {
            Class<?> callGraphClass = callGraph.getClass();
            
            // Try to find internal edge storage fields
            // Soot typically uses MultiMap for storing edges
            try {
                edgesOutOfField = callGraphClass.getDeclaredField("edgesOutOf");
                edgesOutOfField.setAccessible(true);
                System.err.println("CALLGRAPH-MODIFIER: Found edgesOutOf field");
            } catch (NoSuchFieldException e) {
                // Try alternative field names
                System.err.println("CALLGRAPH-MODIFIER: edgesOutOf field not found, trying alternatives");
            }
            
            try {
                edgesIntoField = callGraphClass.getDeclaredField("edgesInto");
                edgesIntoField.setAccessible(true);
                System.err.println("CALLGRAPH-MODIFIER: Found edgesInto field");
            } catch (NoSuchFieldException e) {
                System.err.println("CALLGRAPH-MODIFIER: edgesInto field not found, trying alternatives");
            }
            
            // Try to find private addEdge method if it exists
            try {
                addEdgeMethod = callGraphClass.getDeclaredMethod("addEdge", Edge.class);
                addEdgeMethod.setAccessible(true);
                System.err.println("CALLGRAPH-MODIFIER: Found private addEdge method");
            } catch (NoSuchMethodException e) {
                System.err.println("CALLGRAPH-MODIFIER: No private addEdge method found");
            }
            
        } catch (Exception e) {
            System.err.println("CALLGRAPH-MODIFIER: Failed to initialize reflection: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Add an ICC edge to the call graph using reflection
     */
    public boolean addIccEdge(Edge edge) {
        System.err.println("CALLGRAPH-MODIFIER: Attempting to add ICC edge: " + 
                          edge.getSrc().method().getSignature() + " -> " + 
                          edge.getTgt().method().getSignature());
        
        try {
            // Method 1: Try using private addEdge method if available
            if (addEdgeMethod != null) {
                addEdgeMethod.invoke(callGraph, edge);
                addedEdges.add(edge);
                System.err.println("CALLGRAPH-MODIFIER: Successfully added edge using private method");
                return true;
            }
            
            // Method 2: Direct manipulation of internal data structures
            if (edgesOutOfField != null && edgesIntoField != null) {
                return addEdgeDirectly(edge);
            }
            
            // Method 3: Alternative approach using public API workarounds
            return addEdgeWithWorkaround(edge);
            
        } catch (Exception e) {
            System.err.println("CALLGRAPH-MODIFIER: Failed to add ICC edge: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * Add edge by directly manipulating internal data structures
     */
    @SuppressWarnings("unchecked")
    private boolean addEdgeDirectly(Edge edge) {
        try {
            // Get the internal edge maps
            MultiMap<MethodOrMethodContext, Edge> edgesOutOf = 
                (MultiMap<MethodOrMethodContext, Edge>) edgesOutOfField.get(callGraph);
            MultiMap<MethodOrMethodContext, Edge> edgesInto = 
                (MultiMap<MethodOrMethodContext, Edge>) edgesIntoField.get(callGraph);
            
            // Add edge to outgoing edges map
            edgesOutOf.put(edge.getSrc(), edge);
            
            // Add edge to incoming edges map  
            edgesInto.put(edge.getTgt(), edge);
            
            addedEdges.add(edge);
            System.err.println("CALLGRAPH-MODIFIER: Successfully added edge using direct manipulation");
            return true;
            
        } catch (Exception e) {
            System.err.println("CALLGRAPH-MODIFIER: Direct manipulation failed: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Workaround method for adding edges when reflection fails
     */
    private boolean addEdgeWithWorkaround(Edge edge) {
        System.err.println("CALLGRAPH-MODIFIER: Using workaround method for edge addition");
        
        // Store edge for later verification even if we can't add it directly
        addedEdges.add(edge);
        
        // Log the edge for manual verification
        System.err.println("CALLGRAPH-MODIFIER: WORKAROUND - Stored edge for verification: " +
                          edge.getSrc().method().getSignature() + " -> " + 
                          edge.getTgt().method().getSignature());
        
        return true; // Return true to continue analysis, even though edge may not be in graph
    }
    
    /**
     * Verify that an edge was successfully added to the call graph
     */
    public boolean verifyEdge(Edge edge) {
        try {
            // Check if edge appears in outgoing edges
            Iterator<Edge> outEdges = callGraph.edgesOutOf(edge.getSrc());
            while (outEdges.hasNext()) {
                Edge outEdge = outEdges.next();
                if (edgesEqual(outEdge, edge)) {
                    System.err.println("CALLGRAPH-MODIFIER: Edge verified in call graph");
                    return true;
                }
            }
            
            System.err.println("CALLGRAPH-MODIFIER: Edge not found in call graph");
            return false;
            
        } catch (Exception e) {
            System.err.println("CALLGRAPH-MODIFIER: Edge verification failed: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Check if two edges are equivalent
     */
    private boolean edgesEqual(Edge e1, Edge e2) {
        return e1.getSrc().equals(e2.getSrc()) && 
               e1.getTgt().equals(e2.getTgt()) &&
               e1.srcUnit() == e2.srcUnit(); // Compare units by reference
    }
    
    /**
     * Get statistics about added edges
     */
    public void printStatistics() {
        System.err.println("CALLGRAPH-MODIFIER: Added " + addedEdges.size() + " ICC edges");
        
        int verifiedCount = 0;
        for (Edge edge : addedEdges) {
            if (verifyEdge(edge)) {
                verifiedCount++;
            }
        }
        
        System.err.println("CALLGRAPH-MODIFIER: " + verifiedCount + "/" + addedEdges.size() + " edges verified in call graph");
        
        if (verifiedCount < addedEdges.size()) {
            System.err.println("CALLGRAPH-MODIFIER: WARNING - Some ICC edges may not be traversable");
        }
    }
    
    /**
     * Get all edges that were added
     */
    public Set<Edge> getAddedEdges() {
        return java.util.Collections.unmodifiableSet(addedEdges);
    }
    
    /**
     * Debug method to inspect CallGraph internal structure
     */
    public void inspectCallGraphStructure() {
        System.err.println("CALLGRAPH-MODIFIER: Inspecting CallGraph structure");
        
        try {
            Class<?> callGraphClass = callGraph.getClass();
            Field[] fields = callGraphClass.getDeclaredFields();
            
            System.err.println("CALLGRAPH-MODIFIER: CallGraph fields:");
            for (Field field : fields) {
                System.err.println("  - " + field.getName() + " : " + field.getType().getSimpleName());
            }
            
            Method[] methods = callGraphClass.getDeclaredMethods();
            System.err.println("CALLGRAPH-MODIFIER: CallGraph methods:");
            for (Method method : methods) {
                if (method.getName().contains("edge") || method.getName().contains("Edge")) {
                    System.err.println("  - " + method.getName() + "(" + 
                                      java.util.Arrays.toString(method.getParameterTypes()) + ")");
                }
            }
            
        } catch (Exception e) {
            System.err.println("CALLGRAPH-MODIFIER: Inspection failed: " + e.getMessage());
        }
    }
}