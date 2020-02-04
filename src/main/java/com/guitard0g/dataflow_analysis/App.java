package com.guitard0g.dataflow_analysis;

import fj.data.Array;
import org.apache.log4j.BasicConfigurator;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.solver.cfg.InfoflowCFG;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.internal.JInvokeStmt;
import soot.jimple.internal.JSpecialInvokeExpr;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;
import soot.toolkits.graph.DirectedGraph;
import soot.util.Chain;

import java.io.*;
import java.util.*;

public class App
{
    private static String VIEW_SIG = "android.view.View";

    public static <InfoFlowResults> void main(String[] args) throws IOException, XmlPullParserException {
        BasicConfigurator.configure();
        ResourceQueryEngine queryEngine = App.getResourceInfo();
        String sourceApkPath = "/home/guitard0g/android/memleaks/Memory-Leaks/app/build/outputs/apk/debug/app-debug.apk";
        String androidPlatformPath = "/home/guitard0g/android/sdk/platforms";

        Instrument.instrument(androidPlatformPath, sourceApkPath);

        // Initialize Soot and construct call graph
        String instrumentedApkPath = "./sootOutput/app-debug.apk";
        SetupApplication analyzer = new SetupApplication(androidPlatformPath, instrumentedApkPath);
        analyzer.getConfig().setIgnoreFlowsInSystemPackages(false);
        analyzer.getConfig().setCallgraphAlgorithm(InfoflowConfiguration.CallgraphAlgorithm.CHA);
        analyzer.constructCallgraph();


        // mess with call graph
//        alterCallGraph();


        analyzer.getConfig().setSootIntegrationMode(InfoflowAndroidConfiguration.SootIntegrationMode.UseExistingCallgraph);
//        InfoflowResults res = analyzer.runInfoflow("SourcesAndSinks.txt");
//        InfoflowResults res = analyzer.runInfoflow("SourcesAndSinks.xml");
        InfoflowResults pass1Res = analyzer.runInfoflow(genPass1SourceSinkProvider());
        InfoflowResults pass2Res = analyzer.runInfoflow(genPass2SourceSinkProvider());

//        HashMap<String, HashSet<Unit>> writes = getStaticObjectWrites();
//        alterStaticObjectNullWrites();
//        jas.rightBox.getValue() instanceof NullConstant;

        int x = 1;
    }


    private static CustomSourceSinkProvider genPass1SourceSinkProvider() {
        CustomSourceSinkProvider ssProvider = new CustomSourceSinkProvider();

        StaticUIObjectAnalyzer suob = new StaticUIObjectAnalyzer();
        for(SootField f: suob.getStaticUIObjectFields()) {
            ssProvider.addSinkField(f);
        }

        for (SootMethod m: getSetSinkMethods()) {
            ssProvider.addSourceMethod(m);
        }

        return ssProvider;
    }

    private static CustomSourceSinkProvider genPass2SourceSinkProvider() {
        CustomSourceSinkProvider ssProvider = new CustomSourceSinkProvider();

        ArrayList<SootMethod> nullSets = getNullSetSinkMethods();
        for (SootMethod nullSet: nullSets) {
            ssProvider.addSinkMethod(nullSet);
        }

        for (SootMethod m: getSetSinkMethods()) {
            ssProvider.addSourceMethod(m);
        }

        return ssProvider;
    }

    private static ArrayList<SootMethod>  getViewSourceMethods() {
        CallGraph cg = Scene.v().getCallGraph();
        ArrayList<SootMethod> viewSources = new ArrayList<>();

        for (Iterator<Edge> it = cg.iterator(); it.hasNext(); ) {
            Edge e = it.next();

            if(e.tgt().getReturnType().toString().equals(VIEW_SIG)) {
                viewSources.add(e.tgt());
            }
            if(e.src().getReturnType().toString().equals(VIEW_SIG)) {
                viewSources.add(e.src());
            }
        }

        return viewSources;
    }

    private static HashMap<String, HashSet<Unit>> getStaticObjectWrites() {
        InfoflowCFG icfg = createICFG();
        HashMap<String, HashSet<Unit>> writeMap = new HashMap<>();
        List<SootField> staticFields = (new StaticUIObjectAnalyzer()).getStaticUIObjectFields();

        for (SootField f: staticFields) {
            HashSet<Unit> currWrites = new HashSet<>();

            for (Iterator<Edge> edgeIt = Scene.v().getCallGraph().iterator(); edgeIt.hasNext(); ) {
                Edge edge = edgeIt.next();

                SootMethod smSrc = edge.src();
                SootMethod smDest = edge.tgt();
                if (icfg.isStaticFieldUsed(smSrc, f)) {
                    currWrites.addAll(getFieldWrites(smSrc, f));
                }
                if (icfg.isStaticFieldUsed(smDest, f)) {
                    currWrites.addAll(getFieldWrites(smDest, f));
                }
            }

            writeMap.put(f.getSignature(), currWrites);
        }


        return writeMap;
    }

    private static void alterStaticObjectNullWrites() {
        InfoflowCFG icfg = createICFG();
        List<SootField> staticFields = (new StaticUIObjectAnalyzer()).getStaticUIObjectFields();

        for (SootField f: staticFields) {
            for (Iterator<Edge> edgeIt = Scene.v().getCallGraph().iterator(); edgeIt.hasNext(); ) {
                Edge edge = edgeIt.next();

                SootMethod smSrc = edge.src();
                SootMethod smDest = edge.tgt();
                if (icfg.isStaticFieldUsed(smSrc, f)) {
                    checkNullFieldWrites(smSrc, f);
                }
                if (icfg.isStaticFieldUsed(smDest, f)) {
                    checkNullFieldWrites(smDest, f);
                }
            }
        }
    }

    private static ArrayList<Unit> getFieldWrites(SootMethod m, SootField f) {
        ArrayList<Unit> writes = new ArrayList<>();
        UnitPatchingChain mUnits = m.getActiveBody().getUnits();
        for(Unit u: mUnits) {
            if (u instanceof JAssignStmt) {
                try {
                    if (((JAssignStmt) u).getFieldRef().getField() == f) {
                        writes.add(u);
                    }
                } catch (RuntimeException e) {
                    continue;
                }
            }
        }
        return writes;
    }

    private static void checkNullFieldWrites(SootMethod m, SootField f) {
        UnitPatchingChain mUnits = m.getActiveBody().getUnits();
        for(Unit u: mUnits) {
            if (u instanceof JAssignStmt) {
                try {
                    if (((JAssignStmt) u).getFieldRef().getField() == f) {
                        JAssignStmt jas = ((JAssignStmt) u);
                    }
                } catch (RuntimeException e) {
                    continue;
                }
            }
        }
    }

    private static InfoflowCFG createICFG() {
        InfoflowCFG icfg = new InfoflowCFG();
        System.out.println(Options.v().ignore_resolving_levels());
        for (Iterator<Edge> edgeIt = Scene.v().getCallGraph().iterator(); edgeIt.hasNext(); ) {
            Edge edge = edgeIt.next();

            SootMethod smSrc = edge.src();
            SootMethod smDest = edge.tgt();
            try {
                icfg.getOrCreateUnitGraph(smSrc);
            } catch (RuntimeException ignored) {
               int i = 0;
            }

            try {
                icfg.getOrCreateUnitGraph(smDest);
            } catch (RuntimeException ignored) {
                int i = 0;
            }
        }

        return icfg;
    }


    private static void alterCallGraph() {
        CallGraph cg = Scene.v().getCallGraph();
        Set<Edge> removedEdges = new HashSet<>();

        for (Iterator<Edge> it = cg.iterator(); it.hasNext(); ) {
            Edge e = it.next();

            if (e.tgt().getName().equals("leak") || e.src().getName().equals("leak")) {
                removedEdges.add(e);
            }
        }
        for (Edge e:
                removedEdges) {
            cg.removeAllEdgesOutOf(e.srcUnit());
            cg.removeEdge(e);
            e.tgt().setName("View2");
        }

        Scene.v().setCallGraph(cg);
    }

    private static SootMethod getDummyLeakMethod() {
        CallGraph cg = Scene.v().getCallGraph();

        for (Iterator<Edge> it = cg.iterator(); it.hasNext(); ) {
            Edge e = it.next();

            if (e.tgt().getName().equals("leak")) {
                return e.tgt();
            }
        }
        return null;
    }

    private static ArrayList<SootMethod> getNullSetSinkMethods() {
        CallGraph cg = Scene.v().getCallGraph();
        ArrayList<SootMethod> nullSetMethods = new ArrayList<>();

        for (Iterator<Edge> it = cg.iterator(); it.hasNext(); ) {
            Edge e = it.next();

            if (e.tgt().getName().contains("__SET_NULL__")) {
                nullSetMethods.add(e.tgt());
            }
        }
        return nullSetMethods;
    }

    private static ArrayList<SootMethod> getSetSinkMethods() {
        CallGraph cg = Scene.v().getCallGraph();
        ArrayList<SootMethod> setMethods = new ArrayList<>();

        for (Iterator<Edge> it = cg.iterator(); it.hasNext(); ) {
            Edge e = it.next();

            if (e.tgt().getName().contains("__SET_VAL__")) {
                setMethods.add(e.tgt());
            }
        }
        return setMethods;
    }

    private static SootMethod getDummySinkMethod() {
        CallGraph cg = Scene.v().getCallGraph();

        for (Iterator<Edge> it = cg.iterator(); it.hasNext(); ) {
            Edge e = it.next();

            if (e.tgt().getName().equals("sink")) {
                return e.tgt();
            }
        }
        return null;
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

//    public static <InfoFlowResults> void main(String[] args) throws IOException, XmlPullParserException {
//        BasicConfigurator.configure();
//        ResourceQueryEngine queryEngine = App.getResourceInfo();
////        String appPath = "/home/guitard0g/android/memleaks/android_resource_leaks/testApks/blogLeaks.apk";
////        String appPath = "/home/guitard0g/android/memleaks/android_resource_leaks/testApks/blogSetNull.apk";
//        String appPath = "/home/guitard0g/android/memleaks/Memory-Leaks/app/build/outputs/apk/debug/app-debug.apk";
////        String appPath = "/home/guitard0g/android/memleaks/android_resource_leaks/testApks/app-debug-bad.apk";
//        String androidPlatformPath = "/home/guitard0g/android/sdk/platforms";
//
////        Scene.v().addBasicClass("android.support.v7.widget.ListPopupWindow$ResizePopupRunnable", BODIES);
////        Scene.v().addBasicClass("android.os.AsyncTask", BODIES);
////        Scene.v().addBasicClass("android.widget.AutoCompleteTextView", BODIES);
////        Scene.v().addBasicClass("android.support.v4.widget.ContentLoadingProgressBar$1", BODIES);
//
//        // Initialize Soot and construct call graph
//        SetupApplication analyzer = new SetupApplication(androidPlatformPath, appPath);
////        analyzer.getConfig().setEnableReflection(true);
//        analyzer.getConfig().setIgnoreFlowsInSystemPackages(false);
//        analyzer.getConfig().setCallgraphAlgorithm(InfoflowConfiguration.CallgraphAlgorithm.CHA);
//        analyzer.constructCallgraph();
////        InfoflowResults res = analyzer.runInfoflow("SourcesAndSinks.txt");
//
//
//        // mess with call graph
//        CallGraph cgTest = Scene.v().getCallGraph();
//        Set<Edge> removedEdges = new HashSet<>();
//
//        for (Iterator<Edge> it = cgTest.iterator(); it.hasNext(); ) {
//            Edge e = it.next();
//
//            if (e.tgt().getName().equals("leak") || e.src().getName().equals("leak")) {
//                removedEdges.add(e);
//            }
//        }
//        for (Edge e:
//                removedEdges) {
//            cgTest.removeAllEdgesOutOf(e.srcUnit());
//            cgTest.removeEdge(e);
//            e.tgt().setName("View2");
//        }
//
//        Scene.v().setCallGraph(cgTest);
//
//
//        // end mess with call graph
//
//
//        analyzer.getConfig().setSootIntegrationMode(InfoflowAndroidConfiguration.SootIntegrationMode.UseExistingCallgraph);
//        InfoflowResults res = analyzer.runInfoflow("SourcesAndSinks.xml");
//
//
//        InfoflowCFG icfg = new InfoflowCFG();
////        Options.v().set_ignore_resolving_levels(true);
//        System.out.println(Options.v().ignore_resolving_levels());
//        for (Iterator<Edge> edgeIt = Scene.v().getCallGraph().iterator(); edgeIt.hasNext(); ) {
//            Edge edge = edgeIt.next();
//            Unit srcUnit = edge.srcUnit();
//            List<Unit> test = icfg.getSuccsOf(srcUnit);
//            List<Unit> test2 = icfg.getPredsOf(srcUnit);
//
//            SootMethod smSrc = edge.src();
//            SootMethod smDest = edge.tgt();
//            try {
//                icfg.getOrCreateUnitGraph(smSrc);
//            } catch (RuntimeException e) {
//                continue;
//            }
//            try {
//                icfg.getOrCreateUnitGraph(smDest);
//            } catch (RuntimeException e) {
//                continue;
//            }
//        }
//
////        getOrderings(analyzer, new HashSet<Unit>(), new HashSet<Unit>(), icfg);
//
//
//        // get callgraph and entrypoints for analysis
//        CallGraph cg = Scene.v().getCallGraph();
//        StaticUIObjectAnalyzer suob = new StaticUIObjectAnalyzer(cg);
//
//        List<SootField> test = suob.getStaticUIObjectFields();
//
//        ArrayList<ArrayList<Unit>> sows = getStaticObjectWrites(test, icfg);
//
//        for (SootClass c: Scene.v().getClasses()) {
//            for (SootMethod m: c.getMethods()) {
//                for (SootField field: test) {
//                    if (icfg.isStaticFieldUsed(m, field) ^ icfg.isStaticFieldRead(m, field)) {
//                        System.out.println(m + " : " + field);
//                        try {
//                            DirectedGraph<Unit> graph = icfg.getOrCreateUnitGraph(m);
//                            int dummy = 0;
//                        } catch (RuntimeException e) {
//                            continue;
//                        }
//                    }
//                }
//            }
//        }
//
//
//        // delete
////        Set<SootClass> epcs = analyzer.getEntrypointClasses();
////        for (SootClass c: epcs) {
////            List<SootMethod> ms = c.getMethods();
////            for (SootMethod m: ms) {
////                Body b = m.getActiveBody();
////                for (Unit u: b.getUnits()) {
////                    System.out.println("========================================================");
////                    List<Unit> succs = icfg.getSuccsOf(u);
////                    while (!succs.isEmpty()) {
////                        Unit temp = succs.get(0);
////                        System.out.println(temp);
////                        if (temp instanceof JInvokeStmt) {
////                            JInvokeStmt jis = (JInvokeStmt)temp;
////                            ((JSpecialInvokeExpr)jis.getInvokeExprBox().getValue()).getMethodRef().resolve();
////                            int x = 0;
////                        }
////                        succs.addAll(icfg.getSuccsOf(temp));
////                        succs.remove(0);
////                    }
////                }
////            }
////        }
//        // end delete
//
//        Set<SootClass> entryPointClasses = analyzer.getEntrypointClasses();
//
//        // run analysis
//        AllocationTracker allocationTracker = new AllocationTracker(queryEngine, cg, entryPointClasses);
//        allocationTracker.processCallGraph();
//        allocationTracker.reportLeaks();
//    }


