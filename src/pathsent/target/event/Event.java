package pathsent.target.event;

import pathsent.Output;
import pathsent.target.constraint.Predicate;
import pathsent.target.constraint.Z3ConstraintGenerator;
import pathsent.target.constraint.StringParameterConstraint;
import pathsent.target.constraint.StringParameterZ3Generator;
import pathsent.target.dependency.Dependence;

import soot.*;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

public class Event {
    protected static final SootClass _activityClass =
            Scene.v().getSootClass("android.app.Activity");
    protected static final SootClass _serviceClass =
            Scene.v().getSootClass("android.app.Service");
    protected static final SootClass _receiverClass =
            Scene.v().getSootClass("android.content.BroadcastReceiver");
    protected static final SootClass _viewClass = Scene.v().getSootClass("android.view.View");

    public enum Type {
        NONE,
        ACTIVITY,
        SERVICE,
        RECEIVER,
        UI
    }

    protected final Event.Type _type;
    protected final CallPath _path;
    protected Predicate _constraints;
    protected final List<Dependence> _dependencies = new ArrayList<Dependence>();
    protected List<StringParameterConstraint> _stringParameterConstraints = new ArrayList<>();
    protected Map<String, Object> _metadata = new HashMap<>();

    public Event(CallPath path, Predicate constraints) {
        _path = path;
        _constraints = constraints;
        _type = computeEventType(path.getEntryMethod());
    }

    public CallPath getPath() {
        return _path;
    }

    public Predicate getConstraints() {
        return _constraints;
    }

    public Event.Type getType() {
        return _type;
    }

    public String getTypeString() {
        switch (_type) {
            case ACTIVITY: return "activity";
            case SERVICE:  return "service";
            // TODO: implement intent injection
            case RECEIVER: return "sms";
            case UI:       return "ui";
            default:       return "";
        }
    }

    public void updateConstraints(Predicate constraints) {
        _constraints = constraints;
    }

    public List<Dependence> getDependencies() {
        return _dependencies;
    }

    public void addDependence(Dependence dependence) {
        _dependencies.add(dependence);
    }

    public void addDependencies(Collection<? extends Dependence> dependencies) {
        _dependencies.addAll(dependencies);
    }

    public List<StringParameterConstraint> getStringParameterConstraints() {
        return _stringParameterConstraints;
    }

    public void setStringParameterConstraints(List<StringParameterConstraint> stringParameterConstraints) {
        _stringParameterConstraints = stringParameterConstraints != null ? 
            new ArrayList<>(stringParameterConstraints) : new ArrayList<>();
    }

    public boolean hasConstraints() {
        // Include events with execution constraints OR string parameter constraints
        // This ensures all target method invocations are included in the analysis
        boolean hasStringConstraints = (_stringParameterConstraints != null && !_stringParameterConstraints.isEmpty());
        boolean hasExecutionConstraints = (_constraints != null);
        return hasStringConstraints || hasExecutionConstraints;
    }

    public JsonObject toJson(String eventChainDirectory, int eventId) {
        JsonObject eventJson = new JsonObject();

        eventJson.addProperty("Type", getTypeString());
        eventJson.addProperty("Component",
                _path.getEntryMethod().getDeclaringClass().getName());

        JsonArray pathJson = new JsonArray();
        _path.getNodes().forEach(n -> { pathJson.add(n.method().getSignature()); });
        pathJson.add(_path.getTargetUnit().toString());
        eventJson.add("Path", pathJson);

        // Only create constraint directories and files if we have actual constraints
        String constraintBaseDir = null;
        boolean hasAnyConstraints = hasConstraints();
        
        if (hasAnyConstraints) {
            // Determine vulnerability type and create appropriate directory structure
            constraintBaseDir = determineConstraintDirectory(eventChainDirectory);
            File constraintDir = new File(constraintBaseDir);
            if (!constraintDir.exists()) {
                constraintDir.mkdirs();
            }
        }

        // Generate execution constraints (control flow)
        if (_constraints != null && constraintBaseDir != null) {
            Z3ConstraintGenerator z3Generator = new Z3ConstraintGenerator(_constraints);

            String executionFileName = "execution.py";
            String executionFilePath = constraintBaseDir + "/" + executionFileName;
            writeConstraintFile(executionFilePath, z3Generator.getZ3ConstraintCode());
            eventJson.addProperty("ExecutionConstraintFile", executionFileName);

            eventJson.add("Variables", z3Generator.getZ3VariableMapJson());
        }

        // Generate path constraints (separate from execution constraints)
        if (_stringParameterConstraints != null && !_stringParameterConstraints.isEmpty() && constraintBaseDir != null) {
            StringParameterZ3Generator stringParamGenerator = 
                new StringParameterZ3Generator(_stringParameterConstraints);

            // Determine path constraint file type based on vulnerability type
            StringParameterConstraint.PathType pathType = _stringParameterConstraints.get(0).getPathType();
            String pathFileName;
            
            if (pathType == StringParameterConstraint.PathType.HARD_CODED) {
                // For hijacking: plain text file
                pathFileName = "path.txt";
            } else {
                // For traversal: Z3 constraints
                pathFileName = "path.py";
            }

            String pathFilePath = constraintBaseDir + "/" + pathFileName;
            writeConstraintFile(pathFilePath, stringParamGenerator.generatePathConstraints());
            eventJson.addProperty("PathConstraintFile", pathFileName);

            // Generate metadata file
            String metadataFileName = "metadata.json";
            String metadataFilePath = constraintBaseDir + "/" + metadataFileName;
            writeStringParameterInfoFile(metadataFilePath, stringParamGenerator.getStringParameterInfoJson());
            eventJson.addProperty("MetadataFile", metadataFileName);

            // Add vulnerability classification to JSON
            String vulnType = determineVulnerabilityType(pathType);
            eventJson.addProperty("VulnerabilityType", vulnType);
            eventJson.addProperty("PathType", pathType.toString());
        } else if (_constraints != null) {
            // For execution-only events (no string parameters)
            eventJson.addProperty("VulnerabilityType", "execution_only");
            eventJson.addProperty("PathType", "EXECUTION_ONLY");

            Output.debug("STRING_PARAM: Generated execution_only constraints");
        }

        // TODO
        // UI events
        //public String UIType = null;
        //public String Activities = null;
        //public String Listener = null;
        //public String ListenerMethod = null;
        //public String InDialog = null;

        return eventJson;
    }
    
    /**
     * Determine the appropriate directory structure based on vulnerability type
     */
    private String determineConstraintDirectory(String baseDirectory) {
        String vulnDir;
        
        if (_stringParameterConstraints != null && !_stringParameterConstraints.isEmpty()) {
            // Events with string parameter constraints (file paths)
            StringParameterConstraint.PathType pathType = _stringParameterConstraints.get(0).getPathType();
            
            if (pathType == StringParameterConstraint.PathType.HARD_CODED) {
                vulnDir = "hijacking";
            } else if (pathType == StringParameterConstraint.PathType.PARTIALLY_CONTROLLED) {
                vulnDir = "traversal/partial";
            } else {
                vulnDir = "traversal/full";
            }
        } else {
            // Events with only execution constraints (no string parameters)
            // These are typically write operations, constructor calls, etc.
            vulnDir = "execution_only";
        }
        
        // Extract event ID from base directory path
        String eventIdStr = extractEventId(baseDirectory);
        
        // Get parent directory (package directory)
        File baseDir = new File(baseDirectory);
        String packageDir = baseDir.getParent();
        
        return packageDir + "/" + vulnDir + "/constraints/" + eventIdStr;
    }
    
    /**
     * Extract event ID from constraint directory path
     */
    private String extractEventId(String directoryPath) {
        // Extract number from path like "/path/to/constraints/15"
        File dir = new File(directoryPath);
        return dir.getName();
    }
    
    /**
     * Determine vulnerability type string from PathType
     */
    private String determineVulnerabilityType(StringParameterConstraint.PathType pathType) {
        switch (pathType) {
            case HARD_CODED:
                return "hijacking";
            case PARTIALLY_CONTROLLED:
                return "traversal_partial";
            case FULLY_CONTROLLED:
                return "traversal_full";
            default:
                return "unknown";
        }
    }

    protected void writeConstraintFile(String constraintFilePath, String constraintsCode) {
        try {
            PrintWriter writer = new PrintWriter(constraintFilePath, "UTF-8");
            writer.println("# Start: " + _path.getEntryMethod().getSignature());
            writer.println("# Target: " + _path.getTargetUnit().toString());
            writer.println("");
            writer.print(constraintsCode);
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void writeStringParameterInfoFile(String filePath, JsonObject infoJson) {
        try {
            PrintWriter writer = new PrintWriter(filePath, "UTF-8");
            writer.println(infoJson.toString());
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private Event.Type computeEventType(SootMethod entryMethod) {
        Hierarchy cha = Scene.v().getActiveHierarchy();
        SootClass entryClass = entryMethod.getDeclaringClass();

        // TODO: check if entry method is actually an activity/service entry-point.
        if (entryMethod.getName().equals("onClick")) {
            return Event.Type.UI;

        } else if (!entryClass.isInterface()) {
            if (cha.isClassSubclassOf(entryClass, _activityClass)) {
                return Event.Type.ACTIVITY;
            } else if (cha.isClassSubclassOf(entryClass, _serviceClass)) {
                return Event.Type.SERVICE;
            } else if (cha.isClassSubclassOf(entryClass, _receiverClass)) {
                // TODO: implement intent injection
                return Event.Type.RECEIVER;
            } else {
                if (cha.isClassSubclassOf(entryClass, _viewClass)) {
                    return Event.Type.UI;
                }

                // Also check if this is an implementor of a view-related inner interface.
                for (SootClass interfaceClass : entryClass.getInterfaces()) {
                    String interfaceName = interfaceClass.getName();
                    if (interfaceName.contains("$")) {
                        String outerClassName =
                                interfaceName.substring(0, interfaceName.indexOf('$'));
                        SootClass outerClass = Scene.v().getSootClassUnsafe(outerClassName);
                        if (outerClass != null && !outerClass.isInterface()
                                && cha.isClassSubclassOfIncluding(outerClass, _viewClass)) {

                            return Event.Type.UI;
                        }
                    }
                }
            }
        }

        return Event.Type.NONE;
    }
    
    /**
     * Add metadata to this event
     */
    public void addMetadata(String key, Object value) {
        _metadata.put(key, value);
    }
    
    /**
     * Get metadata from this event
     */
    public Object getMetadata(String key) {
        return _metadata.get(key);
    }
    
    /**
     * Get all metadata
     */
    public Map<String, Object> getAllMetadata() {
        return new HashMap<>(_metadata);
    }
    
    /**
     * Check if event has metadata
     */
    public boolean hasMetadata(String key) {
        return _metadata.containsKey(key);
    }
}
