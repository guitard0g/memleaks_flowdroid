package com.guitard0g.dataflow_analysis;

import soot.SootMethod;
import soot.Unit;
import soot.jimple.Stmt;
import soot.jimple.toolkits.callgraph.Edge;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

public class AllocationTracker {
    private HashSet<String> seen;
    private HashMap<String, SootMethod> seenNotCompleted;
    private HashSet<AllocationPair> completed;
    private HashMap<SootMethod, Stmt> methodToSrcStmt;
    private ResourceQueryEngine qe;

    public AllocationTracker(ResourceQueryEngine qe) {
        seen = new HashSet<>();
        seenNotCompleted = new HashMap<>();
        completed = new HashSet<>();
        methodToSrcStmt = new HashMap<>();
        this.qe = qe;
    }

    public ArrayList<SootMethod> getNotCompleted() {
        ArrayList<SootMethod> notCompleted = new ArrayList<>();
        this.seenNotCompleted.forEach((key, val) -> notCompleted.add(val));
        return notCompleted;
    }

    public HashSet<AllocationPair> getCompleted() {
        return this.completed;
    }

    public Stmt getSrcStmt(SootMethod m) {
        return this.methodToSrcStmt.getOrDefault(m, null);
    }

    public void addNotCompleted(SootMethod m) {
        String key = qe.getKey(m);
        AllocType at = qe.getAllocType(m);
        if (at == AllocType.OPENER) {
            this.seenNotCompleted.put(key, m);
        }
    }

    public void removeNotCompleted(String key) {
        this.seenNotCompleted.remove(key);
    }

    public void processMethod(SootMethod mCaller, SootMethod m) {
        seen.add(qe.getKey(m));
        this.addNotCompleted(m);

        ArrayList<String> matchingKeys = qe.getMatchingKeys(m);
        ArrayList<AllocationPair> allocationPairs = qe.getAllocationPairs(m);
        if (allocationPairs == null || matchingKeys == null) {
            return;
        }

        for (int i=0; i<matchingKeys.size(); i++) {
            String matchingKey = matchingKeys.get(i);
            AllocationPair allocationPair = allocationPairs.get(i);
            allocationPair.addCallingMethod(mCaller, m);
            if (seen.contains(matchingKey)) {
                // remove from not completed
                removeNotCompleted(matchingKey);
                removeNotCompleted(qe.getKey(m));
                // add alloc pair to completed set
                completed.add(allocationPair);
            }
        }
    }

    public void processEdge(Edge edge) {
        SootMethod src = edge.src();
        SootMethod dest = edge.tgt();
        this.methodToSrcStmt.put(src, edge.srcStmt());

        AllocType at = qe.getAllocType(dest);
        switch (at) {
            case NONE: return;
            default: processMethod(src, dest);
        }
    }
}
