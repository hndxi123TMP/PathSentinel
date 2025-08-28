package pathsent.target.constraint;

import pathsent.Output;

import soot.SootMethod;
import soot.Value;
import soot.jimple.InvokeExpr;
import soot.jimple.StringConstant;

import java.util.List;
import java.util.Set;

public class MethodCallVariable extends SymbolicVariable {
    private final InvokeExpr _invokeExpr;
    private final Variable _receiver;
    private final Variable[] _parameters;
    private final String[] _stringParameters; // Store string parameter values

    public MethodCallVariable(InvokeExpr invokeExpr) {
        this(invokeExpr, null, null);
    }

    public MethodCallVariable(InvokeExpr invokeExpr, Variable receiver) {
        this(invokeExpr, receiver, null);
    }

    public MethodCallVariable(InvokeExpr invokeExpr, Variable receiver,
                              Variable[] parameters) {
        super((receiver != null ? receiver.toString() :
                invokeExpr.getMethodRef().declaringClass().getShortName()) + "."
                        + invokeExpr.getMethodRef().name() + "(){" + invokeExpr.hashCode()
                        + "}",
              invokeExpr.getMethod().getReturnType());
        _invokeExpr = invokeExpr;
        _receiver = receiver;
        _parameters = parameters == null ? null : parameters.clone();
        _stringParameters = extractStringParameters(invokeExpr);
    }

    /**
     * Extract string parameter values from the InvokeExpr
     */
    private String[] extractStringParameters(InvokeExpr invokeExpr) {
        String[] stringParams = new String[invokeExpr.getArgCount()];
        
        for (int i = 0; i < invokeExpr.getArgCount(); i++) {
            Value arg = invokeExpr.getArg(i);
            if (arg instanceof StringConstant) {
                StringConstant stringConstant = (StringConstant) arg;
                // Remove surrounding quotes
                String value = stringConstant.toString();
                if (value.startsWith("\"") && value.endsWith("\"") && value.length() >= 2) {
                    stringParams[i] = value.substring(1, value.length() - 1);
                } else {
                    stringParams[i] = value;
                }
            } else {
                stringParams[i] = null; // Non-string or non-constant parameter
            }
        }
        
        return stringParams;
    }

    public Variable getReceiverVariable() {
        return _receiver;
    }

    public SootMethod getMethod() {
        return _invokeExpr.getMethod();
    }
    
    /**
     * Get the InvokeExpr associated with this method call
     */
    public InvokeExpr getInvokeExpr() {
        return _invokeExpr;
    }
    
    /**
     * Get the string parameter values (null for non-string parameters)
     */
    public String[] getStringParameters() {
        return _stringParameters.clone();
    }
    
    /**
     * Get a specific string parameter by index
     */
    public String getStringParameter(int index) {
        if (index >= 0 && index < _stringParameters.length) {
            return _stringParameters[index];
        }
        return null;
    }
    
    /**
     * Check if a specific parameter is a string constant
     */
    public boolean hasStringParameter(int index) {
        return getStringParameter(index) != null;
    }
    
    /**
     * Get method call description with parameter information for debugging
     */
    public String getMethodCallDescription() {
        StringBuilder sb = new StringBuilder();
        
        String receiver = _receiver != null ? _receiver.toString() :
                _invokeExpr.getMethodRef().declaringClass().getShortName();
        
        sb.append(receiver).append(".").append(_invokeExpr.getMethodRef().name()).append("(");
        
        for (int i = 0; i < _stringParameters.length; i++) {
            if (i > 0) sb.append(", ");
            if (_stringParameters[i] != null) {
                sb.append("\"").append(_stringParameters[i]).append("\"");
            } else {
                sb.append("?");
            }
        }
        
        sb.append(")");
        return sb.toString();
    }

    //@Override
    //public String toString() {
    //    String receiver = _receiver != null ? _receiver.toString() :
    //            _invokeExpr.getMethodRef().declaringClass().getShortName();


    //    return receiver + "." + _invokeExpr.getMethodRef().name() + "(" +
    //            _invokeExpr.hashCode() + ")" + "<return>";
    //}

    @Override
    public boolean dependsOnInput() {
        if (_receiver != null && _receiver.dependsOnInput()) {
            return true;
        }
        //for (Variable parameter : _parameters) {
        //    if (parameter != null && parameter.dependsOnInput()) {
        //        return true;
        //    }
        //}

        return false;
    }

    @Override
    public boolean dependsOnInput(int inputNumber) {
        if (_receiver != null && _receiver.dependsOnInput(inputNumber)) {
            return true;
        }

        return false;
    }

    @Override
    public Set<Variable> getAllVariables(Set<Variable> set) {
        set.add(this);
        if (_receiver != null) {
            _receiver.getAllVariables(set);
        }
        return set;
    }

    @Override public boolean isInputVariable() { return false; }
    @Override public boolean isSystemVariable() { return false; }
    @Override public boolean isHeapVariable() { return false; }

    //@Override
    //public boolean isInputVariable() {
    //    if (_receiver == null || !_receiver.isSymbolic()) {
    //        return false;
    //    }

    //    SymbolicVariable symbolicReceiver = (SymbolicVariable)_receiver;
    //    return symbolicReceiver.isInputVariable();
    //}

    //@Override
    //public boolean isSystemVariable() {
    //    if (_receiver == null || !_receiver.isSymbolic()) {
    //        return false;
    //    }

    //    SymbolicVariable symbolicReceiver = (SymbolicVariable)_receiver;
    //    return symbolicReceiver.isSystemVariable();

    //    //for (Variable parameter : _parameters) {
    //    //    if (parameter != null && parameter.isSystemVariable()) {
    //    //        return true;
    //    //    }
    //    //}
    //}

    //@Override
    //public boolean isHeapVariable() {
    //    return false;
    //}

}
