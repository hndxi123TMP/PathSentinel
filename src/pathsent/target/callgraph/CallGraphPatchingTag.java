package pathsent.target.callgraph;

import soot.SootMethod;
import soot.tagkit.AttributeValueException;
import soot.tagkit.Tag;

/**
 * Replacement for the removed soot.jimple.toolkits.callgraph.CallGraphPatchingTag
 * This is a simplified version for PathSentinel's Android call graph patching needs.
 */
public class CallGraphPatchingTag implements Tag {
    
    public enum Kind {
        Activity, Service, BroadcastReceiver, Executor, AsyncTask, Intent, Thread, Messenger
    }
    
    private final Kind kind;
    private final SootMethod targetMethod;
    
    public CallGraphPatchingTag(Kind kind, SootMethod targetMethod) {
        this.kind = kind;
        this.targetMethod = targetMethod;
    }
    
    public Kind getKind() {
        return kind;
    }
    
    public SootMethod getTargetMethod() {
        return targetMethod;
    }
    
    @Override
    public String getName() {
        return "CallGraphPatchingTag";
    }
    
    @Override
    public byte[] getValue() throws AttributeValueException {
        return new byte[0];
    }
    
    @Override
    public String toString() {
        return "CallGraphPatchingTag[" + kind + ", " + targetMethod + "]";
    }
}