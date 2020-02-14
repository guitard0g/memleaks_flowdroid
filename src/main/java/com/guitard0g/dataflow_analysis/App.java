package com.guitard0g.dataflow_analysis;


import org.apache.log4j.BasicConfigurator;
import soot.*;
import soot.jimple.infoflow.InfoflowConfiguration;
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

        HashMap<Integer, DummyCallInfo> dummyDecoder = Instrument.instrument(androidPlatformPath, sourceApkPath);

        // Initialize Soot and construct call graph
        String instrumentedApkPath = "./sootOutput/" + filename;
        SetupApplication analyzer = new SetupApplication(androidPlatformPath, instrumentedApkPath);
        analyzer.getConfig().setCallgraphAlgorithm(InfoflowConfiguration.CallgraphAlgorithm.CHA);
        analyzer.constructCallgraph();


//        analyzer.getConfig().setSootIntegrationMode(InfoflowAndroidConfiguration.SootIntegrationMode.UseExistingCallgraph);
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

        for (SootMethod m: ssp.getSourceMethods()) {
            if (!closedPaths.contains(m.getSignature())) {
                displayLeakedField(m, dummyDecoder);
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

    private static void displayLeakedField(SootMethod m, HashMap<Integer, DummyCallInfo> decoder) {
        int sourceSuffix = getIntSuffix(m);
        DummyCallInfo source = decoder.get(sourceSuffix);
        System.out.println("PATH NOT CLOSED (POTENTIAL LEAK): ");
        System.out.println("Variable: ");
        System.out.println("\t" + source.f);
        System.out.println("SOURCE: ");
        System.out.println("\t" + source.m);
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
}

