package com.guitard0g.dataflow_analysis;

import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.solver.cfg.InfoflowCFG;
import soot.jimple.infoflow.sourcesSinks.definitions.SourceSinkDefinition;
import soot.jimple.toolkits.callgraph.CallGraph;
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
        String appPath = "/home/guitard0g/android/memleaks/android_resource_leaks/testApks/app-debug.apk";
        String androidPlatformPath = "/home/guitard0g/android/sdk/platforms";

        Options.v().set_whole_program(true);
        Scene.v().addBasicClass("java.lang.StringBuilder",BODIES);


        // Initialize Soot
        SetupApplication analyzer = new SetupApplication(androidPlatformPath, appPath);
        analyzer.getConfig().setTaintAnalysisEnabled(false);

        // options
        InfoflowAndroidConfiguration ifConfig = analyzer.getConfig();

        analyzer.constructCallgraph();
        Set<String> cbs = analyzer.getCallbackClasses();
        Set<SourceSinkDefinition> ss = analyzer.getSources();
        Set<SootClass> epc = analyzer.getEntrypointClasses();
        for (SootClass sc:
             epc) {
        }
        CallGraph cg = Scene.v().getCallGraph();

        SootMethod onc = null;
        SootMethod getCam = null;

        InfoflowCFG icfg = new InfoflowCFG();


        AllocationTracker allocationTracker = new AllocationTracker();
        // Iterate over the callgraph
        for (Iterator<Edge> edgeIt = cg.iterator(); edgeIt.hasNext(); ) {
            Edge edge = edgeIt.next();

            SootMethod smSrc = edge.src();
            SootMethod smDest = edge.tgt();

            allocationTracker.processEdge(edge, queryEngine);

            Unit uSrc = edge.srcStmt();
            if (smSrc.getName().equals("getCameraInstance")) {
                getCam = smSrc;
            } else if (smSrc.getName().equals("onCreate")) {
                onc = smSrc;
            }

            System.out.println("Edge from " + uSrc + " in " + smSrc + " to " + smDest);
        }
        ArrayList<SootMethod> entryPoints = new ArrayList<>();
        entryPoints.add(analyzer.getDummyMainMethod());

        ReachableMethods rm = new ReachableMethods(cg, entryPoints);
        rm.update();
        boolean x = rm.contains(getCam);
        System.out.println("test");
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
                    AllocationPair rp = new AllocationPair(text);
                    qe.pairMap.put(text, rp);
                    qe.closeToOpenMap.put(rp.closeKey, rp.opener);
                    qe.openToCloseMap.put(rp.openKey, rp.closer);
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
