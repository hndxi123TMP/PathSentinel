package pathsent.target.entrypoint;

import soot.MethodOrMethodContext;
import soot.SootMethod;
import java.util.Set;

/**
 * Interface for entry point analysis implementations
 */
public interface IEntryPointAnalysis {
    /**
     * Get the dummy main method that serves as the entry point
     */
    SootMethod getDummyMainMethod();
    
    /**
     * Get all entry points found by the analysis
     */
    Set<MethodOrMethodContext> getEntryPoints();
}