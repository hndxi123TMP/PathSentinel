package pathsent.target.icc;

import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import pathsent.target.icc.IntentAnalysisHelper.IntentContent;

/**
 * Information about ICC callers (components that initiate inter-component communication)
 * Based on Amandroid's ICC caller patterns
 */
public abstract class ICCCallerInfo implements ComponentSummaryTable.CallerInfo {
    protected final SootClass component;
    protected final SootMethod method;
    protected final Unit callSite;
    
    public ICCCallerInfo(SootClass component, SootMethod method, Unit callSite) {
        this.component = component;
        this.method = method;
        this.callSite = callSite;
    }
    
    @Override
    public SootClass getComponent() {
        return component;
    }
    
    public SootMethod getMethod() {
        return method;
    }
    
    public Unit getCallSite() {
        return callSite;
    }
    
    /**
     * Intent-based caller (startActivity, sendBroadcast, startService, etc.)
     */
    public static class IntentCaller extends ICCCallerInfo {
        private final IntentContent intentContent;
        private final String iccMethod;
        
        public IntentCaller(SootClass component, SootMethod method, Unit callSite, 
                           IntentContent intentContent, String iccMethod) {
            super(component, method, callSite);
            this.intentContent = intentContent;
            this.iccMethod = iccMethod;
        }
        
        @Override
        public String getCallerType() {
            return "IntentCaller";
        }
        
        public IntentContent getIntentContent() {
            return intentContent;
        }
        
        public String getIccMethod() {
            return iccMethod;
        }
        
        @Override
        public String toString() {
            return String.format("IntentCaller{component=%s, method=%s, iccMethod=%s, intent=%s}", 
                component.getName(), method.getSignature(), iccMethod, intentContent);
        }
    }
    
    /**
     * Activity result caller (setResult)
     */
    public static class ActivityResultCaller extends ICCCallerInfo {
        private final int resultCode;
        private final IntentContent resultData;
        
        public ActivityResultCaller(SootClass component, SootMethod method, Unit callSite,
                                  int resultCode, IntentContent resultData) {
            super(component, method, callSite);
            this.resultCode = resultCode;
            this.resultData = resultData;
        }
        
        @Override
        public String getCallerType() {
            return "ActivityResultCaller";
        }
        
        public int getResultCode() {
            return resultCode;
        }
        
        public IntentContent getResultData() {
            return resultData;
        }
        
        @Override
        public String toString() {
            return String.format("ActivityResultCaller{component=%s, method=%s, resultCode=%d}", 
                component.getName(), method.getSignature(), resultCode);
        }
    }
    
    /**
     * Bound service caller
     */
    public static class BoundServiceCaller extends ICCCallerInfo {
        private final String serviceInterface;
        private final String targetMethod;
        
        public BoundServiceCaller(SootClass component, SootMethod method, Unit callSite,
                                String serviceInterface, String targetMethod) {
            super(component, method, callSite);
            this.serviceInterface = serviceInterface;
            this.targetMethod = targetMethod;
        }
        
        @Override
        public String getCallerType() {
            return "BoundServiceCaller";
        }
        
        public String getServiceInterface() {
            return serviceInterface;
        }
        
        public String getTargetMethod() {
            return targetMethod;
        }
        
        @Override
        public String toString() {
            return String.format("BoundServiceCaller{component=%s, method=%s, interface=%s, target=%s}", 
                component.getName(), method.getSignature(), serviceInterface, targetMethod);
        }
    }
    
    /**
     * Messenger caller (Handler.sendMessage)
     */
    public static class MessengerCaller extends ICCCallerInfo {
        private final String messageType;
        
        public MessengerCaller(SootClass component, SootMethod method, Unit callSite, String messageType) {
            super(component, method, callSite);
            this.messageType = messageType;
        }
        
        @Override
        public String getCallerType() {
            return "MessengerCaller";
        }
        
        public String getMessageType() {
            return messageType;
        }
        
        @Override
        public String toString() {
            return String.format("MessengerCaller{component=%s, method=%s, messageType=%s}", 
                component.getName(), method.getSignature(), messageType);
        }
    }
}