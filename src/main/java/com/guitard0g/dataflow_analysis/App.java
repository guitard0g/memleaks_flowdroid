package com.guitard0g.dataflow_analysis;

import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.Stmt;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.solver.cfg.InfoflowCFG;
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
//        String appPath = "/home/guitard0g/android/memleaks/android_resource_leaks/testApks/blogLeaks.apk";
        String appPath = "/home/guitard0g/android/memleaks/android_resource_leaks/testApks/app-debug-bad.apk";
        String androidPlatformPath = "/home/guitard0g/android/sdk/platforms";

//        Scene.v().addBasicClass("android.support.v7.widget.ListPopupWindow$ResizePopupRunnable", BODIES);
//        Scene.v().addBasicClass("android.os.AsyncTask", BODIES);
//        Scene.v().addBasicClass("android.widget.AutoCompleteTextView", BODIES);
//        Scene.v().addBasicClass("android.support.v4.widget.ContentLoadingProgressBar$1", BODIES);

        // Initialize Soot and construct call graph
        SetupApplication analyzer = new SetupApplication(androidPlatformPath, appPath);
        analyzer.getConfig().setEnableReflection(true);
        analyzer.getConfig().setIgnoreFlowsInSystemPackages(false);
        analyzer.getConfig().setCallgraphAlgorithm(InfoflowConfiguration.CallgraphAlgorithm.CHA);
        analyzer.constructCallgraph();
        analyzer.runInfoflow("SourcesAndSinks.txt");


        InfoflowCFG icfg = new InfoflowCFG();

//        Options.v().set_ignore_resolving_levels(true);
        System.out.println(Options.v().ignore_resolving_levels());
        for (Iterator<Edge> edgeIt = Scene.v().getCallGraph().iterator(); edgeIt.hasNext(); ) {
            Edge edge = edgeIt.next();
            Unit srcUnit = edge.srcUnit();
            List<Unit> test = icfg.getSuccsOf(srcUnit);
            List<Unit> test2 = icfg.getPredsOf(srcUnit);

            SootMethod smSrc = edge.src();
            SootMethod smDest = edge.tgt();
            try {
                icfg.getOrCreateUnitGraph(smSrc);
            } catch (RuntimeException e) {
                continue;
            }
            try {
                icfg.getOrCreateUnitGraph(smDest);
            } catch (RuntimeException e) {
                continue;
            }
        }


        // get callgraph and entrypoints for analysis
        CallGraph cg = Scene.v().getCallGraph();
        StaticUIObjectAnalyzer suob = new StaticUIObjectAnalyzer(cg);
        List<SootField> test = suob.getStaticUIObjectFields();
        Set<SootClass> entryPointClasses = analyzer.getEntrypointClasses();

        // run analysis
        AllocationTracker allocationTracker = new AllocationTracker(queryEngine, cg, entryPointClasses);
        allocationTracker.processCallGraph();
        allocationTracker.reportLeaks();
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
