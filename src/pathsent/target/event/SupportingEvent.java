package pathsent.target.event;

import pathsent.target.constraint.Predicate;
import pathsent.target.constraint.Z3Solver;
import pathsent.target.dependency.Dependence;

public class SupportingEvent extends Event {
    protected final Predicate _dependenceConstraint;

    public SupportingEvent(CallPath path, Predicate constraints,
            Predicate dependenceConstraint) {
        super(path, constraints);
        _dependenceConstraint = dependenceConstraint;
    }

    public Predicate getDependenceConstraint() {
        return _dependenceConstraint;
    }

    public boolean canResolveDependencyForEvent(Event event, Dependence dependence) {
        // Check dependence constraint using the Z3 solver.
        Predicate combinedDepConstraint = Predicate.combine(Predicate.Operator.AND,
                _dependenceConstraint, event.getConstraints());
        return Z3Solver.isSatisfiable(combinedDepConstraint);

        //if ((_constraints == null || !_constraints.isOppositeOf(eventConstraints))
        //        && !_dependenceConstraint.isOppositeOf(eventConstraints)) {
        //    return true;
        //}
        //return false;
    }

    @Override
    public SupportingEvent clone() {
        return new SupportingEvent(_path, _constraints, _dependenceConstraint);
    }
}
