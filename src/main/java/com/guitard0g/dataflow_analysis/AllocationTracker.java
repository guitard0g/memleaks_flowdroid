package com.guitard0g.dataflow_analysis;

import soot.Kind;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.Stmt;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.callgraph.ReachableMethods;

import java.lang.reflect.Array;
import java.util.*;

public class AllocationTracker {
    private HashSet<String> seen;
    private HashMap<String, SootMethod> seenNotCompleted;
    private HashSet<AllocationPair> completed;
    private HashMap<SootMethod, Stmt> methodToSrcStmt;
    private HashSet<SootMethod> appExitPoints;

    private ResourceQueryEngine qe;
    private CallGraph cg;
    private Set<SootClass> entryPointClasses;

    public AllocationTracker(ResourceQueryEngine qe, CallGraph cg, Set<SootClass> entryPointClasses) {
        seen = new HashSet<>();
        seenNotCompleted = new HashMap<>();
        completed = new HashSet<>();
        methodToSrcStmt = new HashMap<>();
        this.appExitPoints = new HashSet<>();
        this.qe = qe;
        this.cg = cg;
        this.entryPointClasses = entryPointClasses;
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

    public void processCallGraph() {
        for (Iterator<Edge> edgeIt = cg.iterator(); edgeIt.hasNext(); ) {
            Edge edge = edgeIt.next();
            processEdge(edge);

            SootMethod smSrc = edge.src();
            SootMethod smDest = edge.tgt();
            if (isExitPoint(smSrc, entryPointClasses)) {
                appExitPoints.add(smSrc);
            }
            if (isExitPoint(smDest, entryPointClasses)) {
                appExitPoints.add(smDest);
            }
        }
    }

    public void reportLeaks() {
        for (AllocationPair allocationPair: getCompleted()) {
            ArrayList<SootMethod> callingOpeners = allocationPair.getOpenerCallingMethods();
            for (SootMethod caller: callingOpeners) {
                Stmt dummySrcStmt = getSrcStmt(caller);
                if (dummySrcStmt != null) {
                    for (SootMethod exitPoint: appExitPoints) {
                        Edge newEdge = new Edge(caller, dummySrcStmt, exitPoint, Kind.VIRTUAL);
                        cg.addEdge(newEdge);
                    }
                }
            }

            for (SootMethod opener: callingOpeners) {
                ArrayList<SootMethod> entryPoints = new ArrayList<>();
                entryPoints.add(opener);
                ReachableMethods rm = new ReachableMethods(cg, entryPoints);
                rm.update();
                boolean found = false;
                for (SootMethod closer: allocationPair.getCloserCallingMethods()) {
                    if (rm.contains(closer))
                        found = true;
                }
                if (!found) {
                    System.out.println("Potential system resource leak: " + opener);
                }
            }

        }
        for (SootMethod opener: getNotCompleted()) {
            System.out.println("Potential system resource leak: " + opener);
        }
    }

    private static boolean isExitPoint(SootMethod m, Set<SootClass> entryPointClasses) {
        if (!entryPointClasses.contains(m.getDeclaringClass())) {
            return false;
        }

        String mName = m.getName();
        if (mName.equals("onStop") || mName.equals("onPause") || mName.equals("onDestroy")) {
            return true;
        }

        return false;
    }
}
