package pathsent.target.icc;

import java.util.*;
import pathsent.target.icc.IntentAnalysisHelper.IntentContent;
import pathsent.target.icc.IntentAnalysisHelper.UriData;

/**
 * Represents an Android IntentFilter for matching incoming Intents
 * Based on Amandroid's IntentFilter implementation
 */
public class IntentFilter {
    private final Set<String> actions;
    private final Set<String> categories;
    private final Set<UriData> data;
    private final Set<String> mimeTypes;
    private final String componentType;
    
    public IntentFilter(String componentType) {
        this.componentType = componentType;
        this.actions = new HashSet<>();
        this.categories = new HashSet<>();
        this.data = new HashSet<>();
        this.mimeTypes = new HashSet<>();
    }
    
    // Getters
    public Set<String> getActions() {
        return Collections.unmodifiableSet(actions);
    }
    
    public Set<String> getCategories() {
        return Collections.unmodifiableSet(categories);
    }
    
    public Set<UriData> getData() {
        return Collections.unmodifiableSet(data);
    }
    
    public Set<String> getMimeTypes() {
        return Collections.unmodifiableSet(mimeTypes);
    }
    
    public String getComponentType() {
        return componentType;
    }
    
    // Adders
    public void addAction(String action) {
        if (action != null && !action.isEmpty()) {
            actions.add(action);
        }
    }
    
    public void addCategory(String category) {
        if (category != null && !category.isEmpty()) {
            categories.add(category);
        }
    }
    
    public void addData(UriData uriData) {
        if (uriData != null) {
            data.add(uriData);
        }
    }
    
    public void addMimeType(String mimeType) {
        if (mimeType != null && !mimeType.isEmpty()) {
            mimeTypes.add(mimeType);
        }
    }
    
    /**
     * Check if this IntentFilter matches the given IntentContent
     */
    public boolean matches(IntentContent intent) {
        // Check actions
        if (!actions.isEmpty() && !intent.getActions().isEmpty()) {
            boolean actionMatches = false;
            for (String intentAction : intent.getActions()) {
                if (actions.contains(intentAction) || actions.contains("ANY")) {
                    actionMatches = true;
                    break;
                }
            }
            if (!actionMatches) {
                return false;
            }
        }
        
        // Check categories - all intent categories must be in the filter
        if (!intent.getCategories().isEmpty()) {
            for (String intentCategory : intent.getCategories()) {
                if (!categories.contains(intentCategory) && !categories.contains("ANY")) {
                    return false;
                }
            }
        }
        
        // Check data/URI matching
        if (!data.isEmpty() && !intent.getUriData().isEmpty()) {
            boolean dataMatches = false;
            for (UriData intentData : intent.getUriData()) {
                for (UriData filterData : data) {
                    if (matchesUriData(filterData, intentData)) {
                        dataMatches = true;
                        break;
                    }
                }
                if (dataMatches) break;
            }
            if (!dataMatches) {
                return false;
            }
        }
        
        // Check MIME types
        if (!mimeTypes.isEmpty() && !intent.getMimeTypes().isEmpty()) {
            boolean typeMatches = false;
            for (String intentType : intent.getMimeTypes()) {
                for (String filterType : mimeTypes) {
                    if (matchesMimeType(filterType, intentType)) {
                        typeMatches = true;
                        break;
                    }
                }
                if (typeMatches) break;
            }
            if (!typeMatches) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Check if filter URI data matches intent URI data
     */
    private boolean matchesUriData(UriData filterData, UriData intentData) {
        // Check scheme
        if (filterData.getScheme() != null && intentData.getScheme() != null) {
            if (!filterData.getScheme().equals(intentData.getScheme())) {
                return false;
            }
        }
        
        // Check host
        if (filterData.getHost() != null && intentData.getHost() != null) {
            if (!filterData.getHost().equals(intentData.getHost())) {
                return false;
            }
        }
        
        // Check port
        if (filterData.getPort() != null && intentData.getPort() != null) {
            if (!filterData.getPort().equals(intentData.getPort())) {
                return false;
            }
        }
        
        // Check path (can be prefix matching)
        if (filterData.getPath() != null && intentData.getPath() != null) {
            if (!intentData.getPath().startsWith(filterData.getPath())) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Check if filter MIME type matches intent MIME type
     * Supports wildcard matching (e.g., "text/*")
     */
    private boolean matchesMimeType(String filterType, String intentType) {
        if (filterType.equals(intentType)) {
            return true;
        }
        
        // Handle wildcards
        if (filterType.endsWith("/*")) {
            String filterBase = filterType.substring(0, filterType.length() - 2);
            return intentType.startsWith(filterBase + "/");
        }
        
        if (filterType.equals("*/*")) {
            return true;
        }
        
        return false;
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        
        IntentFilter that = (IntentFilter) obj;
        return Objects.equals(componentType, that.componentType) &&
               Objects.equals(actions, that.actions) &&
               Objects.equals(categories, that.categories) &&
               Objects.equals(data, that.data) &&
               Objects.equals(mimeTypes, that.mimeTypes);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(componentType, actions, categories, data, mimeTypes);
    }
    
    @Override
    public String toString() {
        return String.format("IntentFilter{component=%s, actions=%s, categories=%s, data=%s, types=%s}", 
            componentType, actions, categories, data, mimeTypes);
    }
}