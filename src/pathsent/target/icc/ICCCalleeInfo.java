package pathsent.target.icc;

import java.util.*;
import soot.SootClass;
import soot.SootMethod;
import pathsent.target.icc.IntentAnalysisHelper.IntentContent;

/**
 * Information about ICC callees (components that receive inter-component communication)
 * Based on Amandroid's ICC callee patterns
 */
public abstract class ICCCalleeInfo implements ComponentSummaryTable.CalleeInfo {
    protected final SootClass component;
    protected final boolean exported;
    protected final Set<String> permissions;
    
    public ICCCalleeInfo(SootClass component, boolean exported, Set<String> permissions) {
        this.component = component;
        this.exported = exported;
        this.permissions = new HashSet<>(permissions);
    }
    
    @Override
    public SootClass getComponent() {
        return component;
    }
    
    public boolean isExported() {
        return exported;
    }
    
    public Set<String> getPermissions() {
        return Collections.unmodifiableSet(permissions);
    }
    
    /**
     * Intent-based callee (Activity, Service, BroadcastReceiver)
     */
    public static class IntentCallee extends ICCCalleeInfo {
        private final Set<IntentFilter> intentFilters;
        private final SootMethod entryMethod;
        
        public IntentCallee(SootClass component, boolean exported, Set<String> permissions,
                           Set<IntentFilter> intentFilters, SootMethod entryMethod) {
            super(component, exported, permissions);
            this.intentFilters = new HashSet<>(intentFilters);
            this.entryMethod = entryMethod;
        }
        
        @Override
        public String getCalleeType() {
            return "IntentCallee";
        }
        
        public Set<IntentFilter> getIntentFilters() {
            return Collections.unmodifiableSet(intentFilters);
        }
        
        public SootMethod getEntryMethod() {
            return entryMethod;
        }
        
        @Override
        public boolean matchesCaller(ComponentSummaryTable.CallerInfo caller) {
            if (!(caller instanceof ICCCallerInfo.IntentCaller)) {
                return false;
            }
            
            ICCCallerInfo.IntentCaller intentCaller = (ICCCallerInfo.IntentCaller) caller;
            IntentContent intent = intentCaller.getIntentContent();
            
            // Check if this component can receive the intent
            return canReceiveIntent(intent, intentCaller.getComponent());
        }
        
        /**
         * Check if this component can receive the given intent
         */
        private boolean canReceiveIntent(IntentContent intent, SootClass callerComponent) {
            // Check export and permission constraints
            if (!exported && !component.equals(callerComponent)) {
                return false; // Not exported and not from same app
            }
            
            // Check explicit intent
            if (intent.isExplicit()) {
                if (intent.isPrecise()) {
                    // Explicit precise intent - check component name
                    return intent.getComponentNames().contains(component.getName());
                } else {
                    // Explicit imprecise intent - could target any component of this type
                    return true;
                }
            }
            
            // Check implicit intent against intent filters
            if (!intent.isExplicit() && !intentFilters.isEmpty()) {
                for (IntentFilter filter : intentFilters) {
                    if (filter.matches(intent)) {
                        return true;
                    }
                }
            }
            
            return false;
        }
        
        @Override
        public String toString() {
            return String.format("IntentCallee{component=%s, exported=%s, filters=%d, entry=%s}", 
                component.getName(), exported, intentFilters.size(), 
                entryMethod != null ? entryMethod.getName() : "null");
        }
    }
    
    /**
     * Activity result callee (onActivityResult)
     */
    public static class ActivityResultCallee extends ICCCalleeInfo {
        private final SootMethod onActivityResult;
        private final Set<SootClass> targetComponents;
        
        public ActivityResultCallee(SootClass component, boolean exported, Set<String> permissions,
                                  SootMethod onActivityResult) {
            super(component, exported, permissions);
            this.onActivityResult = onActivityResult;
            this.targetComponents = new HashSet<>();
        }
        
        @Override
        public String getCalleeType() {
            return "ActivityResultCallee";
        }
        
        public SootMethod getOnActivityResultMethod() {
            return onActivityResult;
        }
        
        public void addTargetComponent(SootClass target) {
            targetComponents.add(target);
        }
        
        public Set<SootClass> getTargetComponents() {
            return Collections.unmodifiableSet(targetComponents);
        }
        
        @Override
        public boolean matchesCaller(ComponentSummaryTable.CallerInfo caller) {
            if (!(caller instanceof ICCCallerInfo.ActivityResultCaller)) {
                return false;
            }
            
            ICCCallerInfo.ActivityResultCaller resultCaller = (ICCCallerInfo.ActivityResultCaller) caller;
            
            // Check if this is the target of a startActivityForResult call
            return targetComponents.contains(resultCaller.getComponent());
        }
        
        @Override
        public String toString() {
            return String.format("ActivityResultCallee{component=%s, targets=%s}", 
                component.getName(), targetComponents.size());
        }
    }
    
    /**
     * Bound service callee
     */
    public static class BoundServiceCallee extends ICCCalleeInfo {
        private final String serviceInterface;
        private final SootMethod serviceMethod;
        private final boolean allowRemote;
        
        public BoundServiceCallee(SootClass component, boolean exported, Set<String> permissions,
                                String serviceInterface, SootMethod serviceMethod, boolean allowRemote) {
            super(component, exported, permissions);
            this.serviceInterface = serviceInterface;
            this.serviceMethod = serviceMethod;
            this.allowRemote = allowRemote;
        }
        
        @Override
        public String getCalleeType() {
            return "BoundServiceCallee";
        }
        
        public String getServiceInterface() {
            return serviceInterface;
        }
        
        public SootMethod getServiceMethod() {
            return serviceMethod;
        }
        
        public boolean isAllowRemote() {
            return allowRemote;
        }
        
        @Override
        public boolean matchesCaller(ComponentSummaryTable.CallerInfo caller) {
            if (!(caller instanceof ICCCallerInfo.BoundServiceCaller)) {
                return false;
            }
            
            ICCCallerInfo.BoundServiceCaller serviceCaller = (ICCCallerInfo.BoundServiceCaller) caller;
            
            // Check interface and method matching
            if (!serviceInterface.equals(serviceCaller.getServiceInterface()) ||
                !serviceMethod.getName().equals(serviceCaller.getTargetMethod())) {
                return false;
            }
            
            // Check remote access permission
            if (!allowRemote && !component.equals(serviceCaller.getComponent())) {
                return false;
            }
            
            return true;
        }
        
        @Override
        public String toString() {
            return String.format("BoundServiceCallee{component=%s, interface=%s, method=%s, remote=%s}", 
                component.getName(), serviceInterface, serviceMethod.getName(), allowRemote);
        }
    }
    
    /**
     * Messenger callee (Handler.handleMessage)
     */
    public static class MessengerCallee extends ICCCalleeInfo {
        private final SootMethod handleMessage;
        
        public MessengerCallee(SootClass component, boolean exported, Set<String> permissions,
                             SootMethod handleMessage) {
            super(component, exported, permissions);
            this.handleMessage = handleMessage;
        }
        
        @Override
        public String getCalleeType() {
            return "MessengerCallee";
        }
        
        public SootMethod getHandleMessageMethod() {
            return handleMessage;
        }
        
        @Override
        public boolean matchesCaller(ComponentSummaryTable.CallerInfo caller) {
            if (!(caller instanceof ICCCallerInfo.MessengerCaller)) {
                return false;
            }
            
            ICCCallerInfo.MessengerCaller messengerCaller = (ICCCallerInfo.MessengerCaller) caller;
            
            // For messenger, typically match within same component or bound services
            return component.equals(messengerCaller.getComponent());
        }
        
        @Override
        public String toString() {
            return String.format("MessengerCallee{component=%s, handleMessage=%s}", 
                component.getName(), handleMessage.getName());
        }
    }
}