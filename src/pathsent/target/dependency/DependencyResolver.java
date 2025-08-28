package pathsent.target.dependency;

import pathsent.target.*;
import pathsent.target.constraint.Predicate;
import pathsent.target.event.CallPath;
import pathsent.target.event.Event;
import pathsent.target.event.SupportingEvent;
import pathsent.target.traversal.CallGraphTraversal;

import java.util.List;

abstract class DependencyResolver<T extends Dependence> {
    public abstract List<CallGraphTraversal.Plugin> getCallGraphPlugins();

    public abstract void computeEventDependencies(Event event);
    public abstract SupportingEvent resolveDependence(Event event, T dependence);
}
