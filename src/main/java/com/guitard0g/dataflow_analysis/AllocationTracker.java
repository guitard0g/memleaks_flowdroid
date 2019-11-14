package com.guitard0g.dataflow_analysis;

import soot.SootMethod;
import soot.jimple.toolkits.callgraph.Edge;

import java.util.HashSet;

public class AllocationTracker {
    private HashSet<String> openers;
    private HashSet<String> closers;
    private HashSet<String> seen;
    private HashSet<AllocationPair> completed;

    public AllocationTracker() {
        openers = new HashSet<>();
        closers = new HashSet<>();
        seen = new HashSet<>();
        completed = new HashSet<>();
    }

    public void processMethod(SootMethod mCaller, SootMethod m, ResourceQueryEngine qe) {
        String matchingKey = qe.getMatchingKey(m);
        if (seen.contains(matchingKey)) {
            // add alloc pair to completed set
            AllocationPair pair = qe.getAllocationPair(m);
            pair.openerCallingMethod = mCaller;
            completed.add(pair);
        } else {
            seen.add(qe.getKey(m));
        }
    }

    public void processEdge(Edge edge, ResourceQueryEngine qe) {
        SootMethod src = edge.src();
        SootMethod dest = edge.tgt();

        AllocType at = qe.getAllocType(dest);
        switch (at) {
            case NONE: return;
            default: processMethod(src, dest, qe);
        }
    }
}
