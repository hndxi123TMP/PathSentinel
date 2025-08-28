package pathsent.target.icc;

import java.util.*;
import soot.SootClass;
import soot.jimple.toolkits.callgraph.Edge;

/**
 * Component Summary Table for tracking inter-component communications
 * Inspired by Amandroid's ComponentSummaryTable for comprehensive ICC analysis
 */
public class ComponentSummaryTable {
    public enum Channel {
        ICC,      // Intent-based inter-component communication
        RPC,      // Remote procedure calls (bound services, messenger)
        STATIC_FIELD // Static field based communication
    }
    
    private final SootClass component;
    private final Map<Channel, ChannelSummary> summaries;
    
    public ComponentSummaryTable(SootClass component) {
        this.component = component;
        this.summaries = new HashMap<>();
        this.summaries.put(Channel.ICC, new ICCSummary());
        this.summaries.put(Channel.RPC, new RPCSummary());
        this.summaries.put(Channel.STATIC_FIELD, new StaticFieldSummary());
    }
    
    public SootClass getComponent() {
        return component;
    }
    
    @SuppressWarnings("unchecked")
    public <T extends ChannelSummary> T getSummary(Channel channel) {
        return (T) summaries.get(channel);
    }
    
    /**
     * Base class for different communication channel summaries
     */
    public abstract static class ChannelSummary {
        protected final Set<CallerInfo> callers = new HashSet<>();
        protected final Set<CalleeInfo> callees = new HashSet<>();
        
        public void addCaller(CallerInfo caller) {
            callers.add(caller);
        }
        
        public void addCallee(CalleeInfo callee) {
            callees.add(callee);
        }
        
        public Set<CallerInfo> getCallers() {
            return Collections.unmodifiableSet(callers);
        }
        
        public Set<CalleeInfo> getCallees() {
            return Collections.unmodifiableSet(callees);
        }
    }
    
    /**
     * ICC (Intent-based) communication summary
     */
    public static class ICCSummary extends ChannelSummary {
        // ICC-specific functionality will be added here
    }
    
    /**
     * RPC (Remote Procedure Call) communication summary
     */
    public static class RPCSummary extends ChannelSummary {
        // RPC-specific functionality will be added here
    }
    
    /**
     * Static field communication summary
     */
    public static class StaticFieldSummary extends ChannelSummary {
        // Static field specific functionality will be added here
    }
    
    // Base interfaces for caller/callee information
    public interface CallerInfo {
        String getCallerType();
        SootClass getComponent();
    }
    
    public interface CalleeInfo {
        String getCalleeType();
        SootClass getComponent();
        boolean matchesCaller(CallerInfo caller);
    }
}