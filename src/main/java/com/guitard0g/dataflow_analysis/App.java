package com.guitard0g.dataflow_analysis;

import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.Stmt;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.solver.cfg.InfoflowCFG;
import soot.jimple.infoflow.sourcesSinks.definitions.SourceSinkDefinition;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.ContextSensitiveCallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.callgraph.ReachableMethods;
import soot.options.Options;

import java.io.*;
import java.util.*;

import static soot.SootClass.BODIES;

public class App
{
    public static void main(String[] args) throws IOException, XmlPullParserException {
        ResourceQueryEngine queryEngine = App.getResourceInfo();
        String appPath = "/home/guitard0g/android/memleaks/android_resource_leaks/testApks/app-debug-bad.apk";
        String androidPlatformPath = "/home/guitard0g/android/sdk/platforms";

        // Initialize Soot
        SetupApplication analyzer = new SetupApplication(androidPlatformPath, appPath);
        analyzer.getConfig().setEnableReflection(true);
        analyzer.getConfig().setIgnoreFlowsInSystemPackages(false);
        analyzer.getConfig().setCallgraphAlgorithm(InfoflowConfiguration.CallgraphAlgorithm.CHA);

        analyzer.constructCallgraph();
        CallGraph cg = Scene.v().getCallGraph();

        HashSet<SootMethod> exitPoints = new HashSet<>();
        Set<SootClass> entryPointClasses = analyzer.getEntrypointClasses();
        AllocationTracker allocationTracker = new AllocationTracker(queryEngine);
        // Iterate over the callgraph
        for (Iterator<Edge> edgeIt = cg.iterator(); edgeIt.hasNext(); ) {
            Edge edge = edgeIt.next();
            allocationTracker.processEdge(edge);

            Unit uSrc = edge.srcStmt();
            SootMethod smSrc = edge.src();
            SootMethod smDest = edge.tgt();
            if (isExitPoint(smSrc, entryPointClasses)) {
                exitPoints.add(smSrc);
            }
            if (isExitPoint(smDest, entryPointClasses)) {
                exitPoints.add(smDest);
            }
        }

        for (AllocationPair allocationPair: allocationTracker.getCompleted()) {
            ArrayList<SootMethod> callingOpeners = allocationPair.getOpenerCallingMethods();
            for (SootMethod caller: callingOpeners) {
                Stmt dummySrcStmt = allocationTracker.getSrcStmt(caller);
                if (dummySrcStmt != null) {
                    for (SootMethod exitPoint: exitPoints) {
                        Edge newEdge = new Edge(caller, dummySrcStmt, exitPoint);
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
        for (SootMethod opener: allocationTracker.getNotCompleted()) {
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

    private static ResourceQueryEngine getResourceInfo() {
        ResourceQueryEngine qe = new ResourceQueryEngine();

        File file = new File("pairs.txt");
        BufferedReader reader = null;

        try {
            reader = new BufferedReader(new FileReader(file));
            String text = null;

            while ((text = reader.readLine()) != null) {
                try {
                    AllocationPair ap = new AllocationPair(text);
                    qe.pairMap.put(text, ap);
                    qe.putCloseToOpenMap(ap.closeKey, ap.opener);
                    qe.putOpenToCloseMap(ap.openKey, ap.closer);
                } catch (AllocationPair.InvalidResourceStringException e) {
                    System.out.println(e);
                }
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (reader != null) {
                    reader.close();
                }
            } catch (IOException e) {
            }
        }
        return qe;
    }
}
