package pathsent.target.icc;

import pathsent.target.ManifestAnalysis;
import pathsent.target.callgraph.AndroidCallGraphPatching;
import pathsent.target.constraint.ConstraintAnalysis;
import pathsent.target.event.Event;
import pathsent.target.event.EventChain;

import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.toolkits.callgraph.CallGraph;

import java.util.*;

/**
 * Integration point for ICC analysis in PathSentinel
 * Connects Amandroid-inspired multi-component analysis with PathSentinel's constraint collection
 */
public class ICCAnalysisIntegration {
    private final ManifestAnalysis manifestAnalysis;
    private final AndroidCallGraphPatching callGraphPatching;
    private MultiComponentAnalysis multiComponentAnalysis;
    
    public ICCAnalysisIntegration(ManifestAnalysis manifestAnalysis, 
                                 AndroidCallGraphPatching callGraphPatching) {
        this.manifestAnalysis = manifestAnalysis;
        this.callGraphPatching = callGraphPatching;
    }
    
    /**
     * Perform ICC analysis and enhance event chains with inter-component dependencies
     */
    public void performICCAnalysis(CallGraph callGraph, List<EventChain> eventChains) {
        System.err.println("PATHSENT-ICC-INTEGRATION: Starting ICC analysis integration");
        
        // Initialize multi-component analysis
        multiComponentAnalysis = new MultiComponentAnalysis(manifestAnalysis, callGraph);
        multiComponentAnalysis.performAnalysis(callGraphPatching);
        
        // Enhance event chains with ICC dependencies
        enhanceEventChainsWithICC(eventChains);
        
        System.err.println("PATHSENT-ICC-INTEGRATION: ICC analysis integration completed");
    }
    
    /**
     * Enhance event chains with inter-component communication dependencies
     */
    private void enhanceEventChainsWithICC(List<EventChain> eventChains) {
        System.err.println("PATHSENT-ICC-INTEGRATION: Enhancing " + eventChains.size() + " event chains with ICC");
        
        Set<MultiComponentAnalysis.ICCLink> iccLinks = multiComponentAnalysis.getICCLinks();
        Set<MultiComponentAnalysis.StaticFieldLink> staticFieldLinks = multiComponentAnalysis.getStaticFieldLinks();
        
        int enhancedChains = 0;
        
        for (EventChain eventChain : eventChains) {
            boolean chainEnhanced = false;
            
            // Check if this event chain involves ICC communication
            for (Event event : eventChain.getEvents()) {
                SootMethod eventMethod = event.getPath().getEntryMethod();
                SootClass eventComponent = eventMethod.getDeclaringClass();
                
                // Check for ICC links from this component
                for (MultiComponentAnalysis.ICCLink link : iccLinks) {
                    if (link.getCaller().getComponent().equals(eventComponent)) {
                        // This event is part of ICC communication
                        addICCDependencyToEvent(event, link);
                        chainEnhanced = true;
                        
                        System.err.println("PATHSENT-ICC-INTEGRATION: Added ICC dependency to event: " + 
                            eventMethod.getSignature() + " -> " + link.getCallee().getComponent().getName());
                    }
                }
                
                // Check for static field links
                for (MultiComponentAnalysis.StaticFieldLink sfLink : staticFieldLinks) {
                    if (sfLink.getWriter().equals(eventComponent) || sfLink.getReader().equals(eventComponent)) {
                        // This event involves static field communication
                        addStaticFieldDependencyToEvent(event, sfLink);
                        chainEnhanced = true;
                        
                        System.err.println("PATHSENT-ICC-INTEGRATION: Added static field dependency to event: " + 
                            eventMethod.getSignature() + " field: " + sfLink.getFieldName());
                    }
                }
            }
            
            if (chainEnhanced) {
                enhancedChains++;
            }
        }
        
        System.err.println("PATHSENT-ICC-INTEGRATION: Enhanced " + enhancedChains + " event chains with ICC dependencies");
    }
    
    /**
     * Add ICC dependency information to an event
     */
    private void addICCDependencyToEvent(Event event, MultiComponentAnalysis.ICCLink link) {
        // Add metadata about ICC communication
        Map<String, Object> iccMetadata = new HashMap<>();
        iccMetadata.put("icc_type", link.getType().toString());
        iccMetadata.put("target_component", link.getCallee().getComponent().getName());
        iccMetadata.put("caller_component", link.getCaller().getComponent().getName());
        
        if (link.getCaller() instanceof ICCCallerInfo.IntentCaller) {
            ICCCallerInfo.IntentCaller intentCaller = (ICCCallerInfo.IntentCaller) link.getCaller();
            iccMetadata.put("intent_method", intentCaller.getIccMethod());
            
            IntentAnalysisHelper.IntentContent intentContent = intentCaller.getIntentContent();
            iccMetadata.put("intent_explicit", intentContent.isExplicit());
            iccMetadata.put("intent_actions", intentContent.getActions());
            iccMetadata.put("intent_categories", intentContent.getCategories());
        }
        
        // Store ICC metadata in event (assuming Event class can store metadata)
        event.addMetadata("icc_dependency", iccMetadata);
    }
    
    /**
     * Add static field dependency information to an event
     */
    private void addStaticFieldDependencyToEvent(Event event, MultiComponentAnalysis.StaticFieldLink link) {
        // Add metadata about static field communication
        Map<String, Object> sfMetadata = new HashMap<>();
        sfMetadata.put("writer_component", link.getWriter().getName());
        sfMetadata.put("reader_component", link.getReader().getName());
        sfMetadata.put("field_name", link.getFieldName());
        
        // Store static field metadata in event
        event.addMetadata("static_field_dependency", sfMetadata);
    }
    
    /**
     * Get discovered inter-component dependencies for external analysis
     */
    public Set<ComponentDependency> getInterComponentDependencies() {
        if (multiComponentAnalysis == null) {
            return Collections.emptySet();
        }
        
        Set<ComponentDependency> dependencies = new HashSet<>();
        
        // Convert ICC links to component dependencies
        for (MultiComponentAnalysis.ICCLink link : multiComponentAnalysis.getICCLinks()) {
            dependencies.add(new ComponentDependency(
                link.getCaller().getComponent(),
                link.getCallee().getComponent(),
                ComponentDependency.Type.ICC,
                link.getType().toString()
            ));
        }
        
        // Convert static field links to component dependencies
        for (MultiComponentAnalysis.StaticFieldLink sfLink : multiComponentAnalysis.getStaticFieldLinks()) {
            dependencies.add(new ComponentDependency(
                sfLink.getWriter(),
                sfLink.getReader(),
                ComponentDependency.Type.STATIC_FIELD,
                sfLink.getFieldName()
            ));
        }
        
        return dependencies;
    }
    
    /**
     * Get analysis statistics
     */
    public ICCAnalysisStats getAnalysisStats() {
        if (multiComponentAnalysis == null) {
            return new ICCAnalysisStats(0, 0, 0);
        }
        
        return new ICCAnalysisStats(
            multiComponentAnalysis.getComponentSummaries().size(),
            multiComponentAnalysis.getICCLinks().size(),
            multiComponentAnalysis.getStaticFieldLinks().size()
        );
    }
    
    /**
     * Represents a dependency between two components
     */
    public static class ComponentDependency {
        public enum Type {
            ICC, STATIC_FIELD
        }
        
        private final SootClass sourceComponent;
        private final SootClass targetComponent;
        private final Type type;
        private final String details;
        
        public ComponentDependency(SootClass sourceComponent, SootClass targetComponent, 
                                 Type type, String details) {
            this.sourceComponent = sourceComponent;
            this.targetComponent = targetComponent;
            this.type = type;
            this.details = details;
        }
        
        public SootClass getSourceComponent() { return sourceComponent; }
        public SootClass getTargetComponent() { return targetComponent; }
        public Type getType() { return type; }
        public String getDetails() { return details; }
        
        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (obj == null || getClass() != obj.getClass()) return false;
            ComponentDependency that = (ComponentDependency) obj;
            return Objects.equals(sourceComponent, that.sourceComponent) &&
                   Objects.equals(targetComponent, that.targetComponent) &&
                   type == that.type &&
                   Objects.equals(details, that.details);
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(sourceComponent, targetComponent, type, details);
        }
        
        @Override
        public String toString() {
            return String.format("ComponentDependency{%s: %s -> %s (%s)}", 
                type, sourceComponent.getName(), targetComponent.getName(), details);
        }
    }
    
    /**
     * Analysis statistics
     */
    public static class ICCAnalysisStats {
        private final int componentCount;
        private final int iccLinkCount;
        private final int staticFieldLinkCount;
        
        public ICCAnalysisStats(int componentCount, int iccLinkCount, int staticFieldLinkCount) {
            this.componentCount = componentCount;
            this.iccLinkCount = iccLinkCount;
            this.staticFieldLinkCount = staticFieldLinkCount;
        }
        
        public int getComponentCount() { return componentCount; }
        public int getIccLinkCount() { return iccLinkCount; }
        public int getStaticFieldLinkCount() { return staticFieldLinkCount; }
        
        @Override
        public String toString() {
            return String.format("ICCAnalysisStats{components=%d, iccLinks=%d, staticFieldLinks=%d}",
                componentCount, iccLinkCount, staticFieldLinkCount);
        }
    }
}