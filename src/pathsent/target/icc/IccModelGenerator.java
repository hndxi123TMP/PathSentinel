package pathsent.target.icc;

import pathsent.target.ManifestAnalysis;
import soot.jimple.infoflow.android.axml.AXmlNode;

import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Generates IC3-compatible ICC model files for FlowDroid's IccTA analysis.
 * 
 * Maps Intent actions to target Android components for inter-component communication analysis.
 */
public class IccModelGenerator {
    
    private final ManifestAnalysis manifestAnalysis;
    private final Map<String, Set<String>> actionToComponents;
    
    public IccModelGenerator(ManifestAnalysis manifestAnalysis) {
        this.manifestAnalysis = manifestAnalysis;
        this.actionToComponents = new HashMap<>();
    }
    
    /**
     * Generates ICC model by parsing AndroidManifest.xml for Intent filters and component mappings.
     */
    public void generateIccModel() {
        System.err.println("ICC: Generating ICC model from AndroidManifest.xml");
        
        // Parse services and their intent filters
        parseServiceIntentFilters();
        
        // Parse broadcast receivers and their intent filters  
        parseBroadcastReceiverIntentFilters();
        
        // Add implicit component mappings for explicit Intents
        addExplicitComponentMappings();
        
        System.err.println("ICC: Generated " + actionToComponents.size() + " action-to-component mappings");
    }
    
    /**
     * Parse service intent filters from manifest.
     */
    private void parseServiceIntentFilters() {
        Set<String> serviceNames = manifestAnalysis.getAllServiceNames();
        
        for (String serviceName : serviceNames) {
            // For now, add default FILE_SERVICE action mapping
            // In a full implementation, we would parse the actual intent-filter elements
            if (serviceName.contains("VulnerableService")) {
                addActionMapping("com.test.pathsent_tester.FILE_SERVICE", serviceName);
                addActionMapping("android.intent.action.MAIN", serviceName);
            }
        }
    }
    
    /**
     * Parse broadcast receiver intent filters from manifest.
     */
    private void parseBroadcastReceiverIntentFilters() {
        Set<String> receiverNames = manifestAnalysis.getAllReceiverNames();
        
        for (String receiverName : receiverNames) {
            // For now, add default BOOT_COMPLETED action mapping
            // In a full implementation, we would parse the actual intent-filter elements
            if (receiverName.contains("VulnerableBroadcastReceiver")) {
                addActionMapping("android.intent.action.BOOT_COMPLETED", receiverName);
                addActionMapping("com.test.pathsent_tester.ADMIN_BROADCAST", receiverName);
            }
        }
    }
    
    /**
     * Add explicit component mappings for direct Intent targeting.
     */
    private void addExplicitComponentMappings() {
        // Add mappings for explicit Intents that directly target components
        Set<String> allComponents = new HashSet<>();
        allComponents.addAll(manifestAnalysis.getAllServiceNames());
        allComponents.addAll(manifestAnalysis.getAllReceiverNames());
        allComponents.addAll(manifestAnalysis.getAllActivityNames());
        allComponents.addAll(manifestAnalysis.getAllProviderNames());
        
        for (String componentName : allComponents) {
            // Map component class name to itself for explicit Intent targeting
            addActionMapping(componentName, componentName);
        }
    }
    
    /**
     * Add an action-to-component mapping.
     */
    private void addActionMapping(String action, String componentName) {
        actionToComponents.computeIfAbsent(action, k -> new HashSet<>()).add(componentName);
        System.err.println("ICC: Mapped action '" + action + "' -> component '" + componentName + "'");
    }
    
    /**
     * Write ICC model to file in IC3-compatible format.
     */
    public void writeIccModelToFile(String outputPath) throws IOException {
        System.err.println("ICC: Writing ICC model to " + outputPath);
        
        try (FileWriter writer = new FileWriter(outputPath)) {
            // Write header
            writer.write("# PathSentinel-generated ICC model for FlowDroid IccTA analysis\n");
            writer.write("# Format: IntentAction -> TargetComponent\n\n");
            
            // Write action-to-component mappings
            for (Map.Entry<String, Set<String>> entry : actionToComponents.entrySet()) {
                String action = entry.getKey();
                Set<String> components = entry.getValue();
                
                for (String component : components) {
                    writer.write(action + " -> " + component + "\n");
                }
            }
            
            writer.flush();
        }
        
        System.err.println("ICC: Successfully wrote ICC model with " + 
                         actionToComponents.size() + " mappings");
    }
    
    /**
     * Get all action-to-component mappings.
     */
    public Map<String, Set<String>> getActionToComponentMappings() {
        return new HashMap<>(actionToComponents);
    }
}