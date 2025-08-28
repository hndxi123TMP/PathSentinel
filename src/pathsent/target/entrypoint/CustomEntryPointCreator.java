package pathsent.target.entrypoint;

import pathsent.Output;

import soot.Body;
import soot.Local;
import soot.MethodOrMethodContext;
import soot.SootClass;
import soot.SootMethod;
import soot.LocalGenerator;
import soot.jimple.Stmt;
import soot.jimple.infoflow.android.entryPointCreators.AndroidEntryPointCreator;
import soot.jimple.infoflow.android.manifest.IManifestHandler;
import soot.util.MultiMap;
import soot.util.HashMultiMap;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

class CustomEntryPointCreator extends AndroidEntryPointCreator {
    private Set<MethodOrMethodContext> _entryPoints =
            new HashSet<MethodOrMethodContext>();

    public CustomEntryPointCreator(IManifestHandler manifest, Collection<SootClass> components) {
        super(manifest, components);
        // Initialize empty collections to avoid null pointer exceptions
        MultiMap<SootClass, SootClass> emptyFragments = new HashMultiMap<>();
        this.setFragments(emptyFragments);
        
        MultiMap<SootMethod, soot.jimple.Stmt> emptyJavaScriptInterfaces = new HashMultiMap<>();
        this.setJavaScriptInterfaces(emptyJavaScriptInterfaces);
    }

    public Set<MethodOrMethodContext> getEntryPoints() {
        return _entryPoints;
    }

    protected Stmt buildMethodCall(SootMethod methodToCall, Local classLocal) {
        _entryPoints.add(methodToCall);
        try {
            java.io.PrintWriter debugFile = new java.io.PrintWriter("/tmp/pathsent_buildmethod_debug.log");
            debugFile.println("buildMethodCall called for: " + methodToCall.getSignature());
            debugFile.println("Current entry points count: " + _entryPoints.size());
            debugFile.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        pathsent.Output.debug("ENTRY POINT: Adding entry point method: " + methodToCall.getSignature());
        return super.buildMethodCall(methodToCall, classLocal);
    }
}
