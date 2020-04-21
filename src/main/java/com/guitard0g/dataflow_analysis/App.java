package com.guitard0g.dataflow_analysis;


import fj.P;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.config.PropertySetter;
import soot.*;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.results.AbstractResultSourceSinkInfo;
import soot.jimple.infoflow.results.DataFlowResult;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

import java.util.*;

public class App
{
    private static String VIEW_SIG = "android.view.View";

    public static <InfoFlowResults> void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Error: wrong number of arguments.");
            System.out.println("Arguments: <path_to_apk> <path_to_android_platforms_dir>");
            System.exit(1);
        }
        String sourceApkPath = args[0];
        String [] apkFilePieces = sourceApkPath.split("/");
        String filename = apkFilePieces[apkFilePieces.length - 1];
        String androidPlatformPath = args[1];


        BasicConfigurator.configure(); // configure logging
        Logger.getRootLogger().setLevel(Level.OFF);

        HashMap<Integer, DummyCallInfo> dummyDecoder = Instrument.instrument(androidPlatformPath, sourceApkPath);

        // Initialize Soot and construct call graph
        String instrumentedApkPath = "./sootOutput/" + filename;
        SetupApplication analyzer = new SetupApplication(androidPlatformPath, instrumentedApkPath);
        analyzer.getConfig().setCallgraphAlgorithm(InfoflowConfiguration.CallgraphAlgorithm.CHA);
        analyzer.constructCallgraph();
        // Important to not repeat work in recreating the callgraph.
        // This also prevents a bug where information is fetched twice and FlowDroid
        //   fails due to finding duplicate classes.
        analyzer.getConfig().setSootIntegrationMode(InfoflowAndroidConfiguration.SootIntegrationMode.UseExistingCallgraph);

        CustomSourceSinkProvider ssp = genSourceSinkProvider();
        InfoflowResults results = analyzer.runInfoflow(ssp);

        HashSet<String> closedPaths = new HashSet<>();
        if (!results.isEmpty()) {
            for(DataFlowResult res: results.getResultSet()) {
                displaySourceSinkResult(res, dummyDecoder);

                SootMethod maybeClosed = getClosedMethod(res, dummyDecoder);
                if (maybeClosed != null) {
                    closedPaths.add(maybeClosed.getSignature());
                }
            }
        }

        CustomSourceSinkProvider resourceSsp = genResourceSourceSinkProvider();
        InfoflowResults resourceResults = analyzer.runInfoflow(resourceSsp);

        HashSet<String> closedResourcePaths = new HashSet<>();
        if (!results.isEmpty()) {
            for(DataFlowResult res: resourceResults.getResultSet()) {
                displaySourceSinkResult(res, dummyDecoder);

                SootMethod maybeClosed = getClosedMethod(res, dummyDecoder);
                if (maybeClosed != null) {
                    closedResourcePaths.add(maybeClosed.getSignature());
                }
            }
        }

        System.out.println("==========================(Potential Leaks)==============================");
        for (SootMethod m: ssp.getSourceMethods()) {
            if (!closedPaths.contains(m.getSignature())) {
                displayLeakedField(m, dummyDecoder);
            }
        }

        System.out.println("==========================(Resources)==============================");
        for (SootMethod m: resourceSsp.getSourceMethods()) {
            if (!closedResourcePaths.contains(m.getSignature())) {
                displayLeakedResource(m, dummyDecoder);
            }
        }


        /**
         * TODO: Check static variable names match for dataflow paths
         * Print out sources without corresponding sinks
         * Print out encapsulating function for any leak instructions
         */
        int x = 1;
    }

    private static SootMethod getClosedMethod(DataFlowResult res, HashMap<Integer, DummyCallInfo> decoder) {
        int sourceSuffix = getIntSuffix(res.getSource());
        int sinkSuffix = getIntSuffix(res.getSink());
        DummyCallInfo source = decoder.get(sourceSuffix);
        DummyCallInfo sink = decoder.get(sinkSuffix);

        if (source.f != sink.f) {
            // invalid result, different variables
            return null;
        } else {
            return res.getSource().getStmt().getInvokeExpr().getMethod();
        }
    }

    private static void displayLeakedResource(SootMethod m, HashMap<Integer, DummyCallInfo> decoder) {
        int sourceSuffix = getIntSuffix(m);
        DummyCallInfo source = decoder.get(sourceSuffix);
        System.out.println("PATH NOT CLOSED (POTENTIAL LEAK): ");
        System.out.println("SOURCE: ");
        System.out.println("\t" + source.resOpen);
        ArrayList<SootMethod> path = getMethodPath(source.m);
        if (path == null) {
            System.out.println("NO PATH TO SOURCE METHOD FOUND.");
            return;
        } else {
            System.out.println("PATH TO SOURCE METHOD: ");
            int i = 0;
            for (SootMethod step: path) {
                System.out.print("\t" + i + ": ");
                System.out.println(step);
                i++;
            }
        }
    }

    private static void displayLeakedField(SootMethod m, HashMap<Integer, DummyCallInfo> decoder) {
        int sourceSuffix = getIntSuffix(m);
        DummyCallInfo source = decoder.get(sourceSuffix);
        if (!source.f.getSignature().contains("View") && !source.f.getSignature().contains("Activity")) {
            return;
        }
        System.out.println("PATH NOT CLOSED (POTENTIAL LEAK): ");
        System.out.println("Variable: ");
        System.out.println("\t" + source.f);
        System.out.println("SOURCE: ");
        System.out.println("\t" + source.m);
        ArrayList<SootMethod> path = getMethodPath(source.m);
        if (path == null) {
            System.out.println("NO PATH TO SOURCE METHOD FOUND.");
            return;
        } else {
            System.out.println("PATH TO SOURCE METHOD: ");
            int i = 0;
            for (SootMethod step: path) {
                System.out.print("\t" + i + ": ");
                System.out.println(step);
                i++;
            }
        }
    }

    public static ArrayList<SootMethod> getMethodPath(SootMethod m) {
        CallGraph cg = Scene.v().getCallGraph();
        // BFS to find SootMethod m
        Set<SootMethod> seen = new HashSet<>();
        Queue<PathBuilder> q = new LinkedList<>();
        for(SootMethod entryPoint: Scene.v().getEntryPoints()) {
            q.add(new PathBuilder(entryPoint, new ArrayList<SootMethod>()));
        }

        while (!q.isEmpty()) {
            PathBuilder next = q.remove();
            seen.add(next.m);
            if (next.m.getSignature().equals(m.getSignature())) {
                return next.path;
            }
            for (Iterator<Edge> it = cg.edgesOutOf(next.m); it.hasNext(); ) {
                Edge e = it.next();

                if (!seen.contains(e.tgt()))
                    q.add(new PathBuilder(e.tgt(), next.path));
            }
        }

        return null;
    }

    private static void displaySourceSinkResult(DataFlowResult res, HashMap<Integer, DummyCallInfo> decoder) {
        int sourceSuffix = getIntSuffix(res.getSource());
        int sinkSuffix = getIntSuffix(res.getSink());
        DummyCallInfo source = decoder.get(sourceSuffix);
        DummyCallInfo sink = decoder.get(sinkSuffix);

        if (source.f != sink.f) {
            // invalid result, different variables
            return;
        }

        System.out.println("DATAFLOW PATH FOUND: ");
        System.out.println("Variable: " + source.f);
        System.out.println("SOURCE: ");
        System.out.println("\t" + source.m);
        System.out.println("SINK: ");
        System.out.println("\t" + sink.m);
    }

    private static int getIntSuffix(AbstractResultSourceSinkInfo res) {
        return getIntSuffix(res.getStmt().getInvokeExpr().getMethod());
    }

    private static int getIntSuffix(SootMethod m) {
        String methodName = m.getName();
        ArrayList<String> pieces = new ArrayList(Arrays.asList(methodName.split("__")));
        String numString = pieces.get(pieces.size() - 1);

        try {
            return Integer.parseInt(numString);
        } catch (NumberFormatException e) {
            System.out.println("Could not parse method suffix: " + e);
            System.exit(1);
            return -1;
        }
    }


    private static CustomSourceSinkProvider genSourceSinkProvider() {
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

    private static CustomSourceSinkProvider genResourceSourceSinkProvider() {
        CustomSourceSinkProvider ssProvider = new CustomSourceSinkProvider();

        ArrayList<SootMethod> sources = getResourceSourceMethods();
        for (SootMethod source: sources) {
            ssProvider.addSourceMethod(source);
        }

        ArrayList<SootMethod> sinks = getResourceSinkMethods();
        for (SootMethod sink: sinks) {
            ssProvider.addSinkMethod(sink);
        }

        return ssProvider;
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

    private static ArrayList<SootMethod> getResourceSourceMethods() {
        CallGraph cg = Scene.v().getCallGraph();
        ArrayList<SootMethod> setMethods = new ArrayList<>();

        for (Iterator<Edge> it = cg.iterator(); it.hasNext(); ) {
            Edge e = it.next();

            if (e.tgt().getName().contains("__OPEN_RES__")) {
                setMethods.add(e.tgt());
            }
        }
        return setMethods;
    }

    private static ArrayList<SootMethod> getResourceSinkMethods() {
        CallGraph cg = Scene.v().getCallGraph();
        ArrayList<SootMethod> setMethods = new ArrayList<>();

        for (Iterator<Edge> it = cg.iterator(); it.hasNext(); ) {
            Edge e = it.next();

            if (e.tgt().getName().contains("__CLOSE_RES__")) {
                setMethods.add(e.tgt());
            }
        }
        return setMethods;
    }
}

class PathBuilder {
    public ArrayList<SootMethod> path;
    public SootMethod m;

    public PathBuilder(SootMethod m, ArrayList<SootMethod> leadingPath) {
        this.path = new ArrayList<>(leadingPath);
        this.path.add(m);
        this.m = m;
    }
}

