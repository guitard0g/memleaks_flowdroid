package com.guitard0g.dataflow_analysis;

import fj.data.Array;
import org.apache.log4j.BasicConfigurator;
import org.xmlpull.v1.XmlPullParserException;
import polyglot.visit.DataFlow;
import soot.*;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.results.DataFlowResult;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

import java.io.*;
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
        String androidPlatformPath = args[1];

        BasicConfigurator.configure(); // configure logging

        Instrument.instrument(androidPlatformPath, sourceApkPath);

        // Initialize Soot and construct call graph
        String instrumentedApkPath = "./sootOutput/app-debug.apk";
        SetupApplication analyzer = new SetupApplication(androidPlatformPath, instrumentedApkPath);
        analyzer.getConfig().setIgnoreFlowsInSystemPackages(false);
        analyzer.getConfig().setCallgraphAlgorithm(InfoflowConfiguration.CallgraphAlgorithm.CHA);
        analyzer.constructCallgraph();


//        analyzer.getConfig().setSootIntegrationMode(InfoflowAndroidConfiguration.SootIntegrationMode.UseExistingCallgraph);
        InfoflowResults results = analyzer.runInfoflow(genSourceSinkProvider());
        for(DataFlowResult res: results.getResultSet()) {
            System.out.println(res);
        }

        /**
         * TODO: Check static variable names match for dataflow paths
         * Print out sources without corresponding sinks
         * Print out encapsulating function for any leak instructions
         */
        int x = 1;
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

