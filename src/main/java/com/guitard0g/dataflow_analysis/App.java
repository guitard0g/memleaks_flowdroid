package com.guitard0g.dataflow_analysis;


import org.apache.commons.cli.*;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.xml.sax.helpers.AttributesImpl;
import org.xmlpull.v1.XmlPullParserException;
import soot.Scene;
import soot.SootMethod;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.jimple.infoflow.results.AbstractResultSourceSinkInfo;
import soot.jimple.infoflow.results.DataFlowResult;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class App
{
    public static String appPackage = "";
    private static int DEFAULT_TIMEOUT = 3600;

    public static void main(String[] args) {
        // get command line arguments
        CliOptions options = parseCliArgs(args);
        // set some Soot global options that we need
        configureSoot();

        // disable logging because it's too verbose
        BasicConfigurator.configure();
        Logger.getRootLogger().setLevel(Level.OFF);

        // run the instrumentation
        HashMap<Integer, DummyCallInfo> dummyDecoder = Instrument.instrument(options.platformPath, options.apkPath, options.resourceMode);

        // initialize Soot and construct call graph
        SetupApplication analyzer = new SetupApplication(options.platformPath, options.instrumentedApkPath);
        // set analyzer options
        configureAnalyzer(analyzer, options.timeout_seconds);

        // we need the manifest to see what our main app package is.
        // we use the main app package inside of our source/sink provider to prune out non-user functions
        // (non-user functions: anything that is LIKELY not written by the app developer)
        try {
            ProcessManifest processMan = new ProcessManifest(options.instrumentedApkPath);
            App.appPackage = processMan.getPackageName();
        } catch (IOException | XmlPullParserException ignored) {}

        if (!options.resourceMode) {
            // MEMORY LEAK STATIC VARIABLE ANALYSIS

            // this source since provider will find all instrumented dummy functions that are related to static vars
            CustomSourceSinkProvider ssp = genSourceSinkProvider();
            // run dataflow analysis with our source sink provider
            InfoflowResults results = analyzer.runInfoflow(ssp);
            // check for timeout (termination state 0 means it terminated normally)
            System.out.println("Termination state (0 is normal): " + results.getTerminationState());

            // Traverse all dataflow paths found.
            // If a path is found for a source, then we know that source is properly cleared and thus not a leak
            HashSet<String> closedPaths = new HashSet<>();
            if (!results.isEmpty()) {
                for(DataFlowResult res: results.getResultSet()) {
                    // Display the dataflow found (not a leak, but potentially useful information for debugging)
                    displaySourceSinkResult(res, dummyDecoder);

                    // it is MAYBE closed because it could be a precision issue that matches up a source and sink for
                    // different variables. It is only truly closed if the source and sink are for the same variable.
                    SootMethod maybeClosed = getClosedMethod(res, dummyDecoder);
                    if (maybeClosed != null) {
                        closedPaths.add(maybeClosed.getSignature());
                    }
                }
            }

            System.out.println("==========================(Potential Leaks)==============================");
            // Display all variables that were not properly cleared.
            // To do this, we look at all static variables that we instrumented and then display all of the ones
            //     that did not have a dataflow path.
            for (SootMethod m: ssp.getSourceMethods()) {
                if (!closedPaths.contains(m.getSignature())) {
                    displayLeakedField(m, dummyDecoder);
                }
            }
        } else {
            // Get the source sink provider for resource allocations/deallocations
            CustomSourceSinkProvider resourceSsp = genResourceSourceSinkProvider();
            // run the dataflow analysis
            InfoflowResults resourceResults = analyzer.runInfoflow(resourceSsp);

            // Similarly to static variables, we collect all resource allocations that are properly cleared
            HashSet<String> closedResourcePaths = new HashSet<>();
            if (!resourceResults.isEmpty()) {
                for(DataFlowResult res: resourceResults.getResultSet()) {
                    displaySourceSinkResult(res, dummyDecoder);

                    SootMethod maybeClosed = getClosedMethod(res, dummyDecoder);
                    if (maybeClosed != null) {
                        closedResourcePaths.add(maybeClosed.getSignature());
                    }
                }
            }

            System.out.println("==========================(Resources)==============================");
            // Similarly to static variables, display non-cleared resources for which no dataflow was found
            for (SootMethod m: resourceSsp.getSourceMethods()) {
                if (!closedResourcePaths.contains(m.getSignature())) {
                    displayLeakedResource(m, dummyDecoder);
                }
            }
        }
    }

    /**
     * Take the command line arguments and parse them into the file paths and options we need to configure the analysis
     *
     * @param args command line argument array
     * @return Parsed CliOptions object
     */
    private static CliOptions parseCliArgs(String[] args) {
        Options options = new Options();

        Option androidPlatformsOpt = new Option("p", "platforms", true, "path to android platforms directory");
        androidPlatformsOpt.setRequired(true);
        options.addOption(androidPlatformsOpt);

        Option apkOpt = new Option("a", "apk", true, "path to APK file to analyze");
        apkOpt.setRequired(true);
        options.addOption(apkOpt);

        Option timeoutOpt = new Option("t", "timeout", true, "Timeout in minutes for the dataflow analysis");
        timeoutOpt.setRequired(false);
        options.addOption(timeoutOpt);

        Option resourceOpt = new Option("r", "resource", false, "flag to switch to system resource analysis");
        options.addOption(resourceOpt);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        try {
            cmd = parser.parse(options, args);

            String platformsPath = cmd.getOptionValue("platforms");
            String apkPath = cmd.getOptionValue("apk");
            boolean resourceMode = cmd.hasOption("resource");
            int timeout = DEFAULT_TIMEOUT;
            if (cmd.hasOption("timout"))
                timeout = Integer.parseInt(cmd.getOptionValue("timeout"));

            return new CliOptions(apkPath, platformsPath, resourceMode, timeout);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("APK analyzer", options);

            System.exit(1);
            return null;
        }
    }

    /**
     *  Set some necessary soot options
     */
    private static void configureSoot() {
        // Basic options for configuring output of instrumentation
        soot.options.Options.v().set_src_prec(soot.options.Options.src_prec_apk);
        soot.options.Options.v().set_output_format(soot.options.Options.output_format_dex);
        soot.options.Options.v().set_force_overwrite(true);

        // Allow phantom references when Soot can't find the source for library functions
        // This allows library functions to be part of our callgraph
        soot.options.Options.v().set_allow_phantom_refs(true);
        soot.options.Options.v().set_allow_phantom_elms(true);

        // These options stop some edge cases for parts of the dex to be pruned from the callgraph
        soot.options.Options.v().set_process_multiple_dex(true);
        soot.options.Options.v().set_whole_program(true);

        // Make soot validate our instrumented APK so that we are instrumenting in a valid way
        soot.options.Options.v().set_validate(true);
    }

    /**
     *  Set some necessary analyzer options
     */
    private static void configureAnalyzer(SetupApplication analyzer, int timeout) {
        // we use this imprecise callgraph algorithm to make sure edges are not pruned out
        analyzer.getConfig().setCallgraphAlgorithm(InfoflowConfiguration.CallgraphAlgorithm.CHA);
        // we need to disable code elimination or else our instrumented functions could disappear
        analyzer.getConfig().setCodeEliminationMode(InfoflowConfiguration.CodeEliminationMode.NoCodeElimination);
        // these two options are mostly unnecessary so disabling them is ok to improve runtime
        analyzer.getConfig().setFlowSensitiveAliasing(false);
        analyzer.getConfig().setEnableArrayTracking(false);
        // 1 hour timeout
        analyzer.getConfig().setDataFlowTimeout(timeout);
        // do an initial callgraph construction so that we have access to the functions for our dataflow analyzer setup
        analyzer.constructCallgraph();
    }

    /**
     * Get the SootMethod object that contains a closed memory or resource
     *
     * @param res Dataflow result with source and sink info
     * @param decoder Metadata for all instrumented methods
     * @return SootMethod of the closed result that this DataFlowResult represents
     */
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

    /**
     * Display resource leak and the first found path to the leak from a program entrypoint
     *
     * @param m SootMethod where the leak occurs
     * @param decoder Metadata for all instrumented functions
     */
    private static void displayLeakedResource(SootMethod m, HashMap<Integer, DummyCallInfo> decoder) {
        int sourceSuffix = getIntSuffix(m);
        DummyCallInfo source = decoder.get(sourceSuffix);
        System.out.println("PATH NOT CLOSED (POTENTIAL LEAK): ");
        System.out.println("SOURCE: ");
        System.out.println("\t" + source.resOpen);
        ArrayList<SootMethod> path = getMethodPath(source.m);
        if (path == null) {
            System.out.println("SOURCE METHOD: ");
            System.out.println("\t" + source.m);
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

    /**
     * Display memory leak and the first found path to the leak from a program entrypoint
     *
     * @param m SootMethod where the leak occurs
     * @param decoder Metadata for all instrumented functions
     */
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
            System.out.println("SOURCE METHOD: ");
            System.out.println("\t" + source.m);
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

    /**
     * Simple BFS to try to find a path to a given method
     *
     * @param m SootMethod target of the search
     * @return call path from an entrypoint to the method
     */
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

    /**
     * Print out info about a dataflow result
     *
     * @param res Dataflow result
     * @param decoder Metadata of all instrumented functions
     */
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
        System.out.println("\t" + sink.resOpen);
    }

    // get the int suffix of an instrumentation function for use with the decoder to retrieve metadata
    private static int getIntSuffix(AbstractResultSourceSinkInfo res) {
        return getIntSuffix(res.getStmt().getInvokeExpr().getMethod());
    }

    // get the int suffix of an instrumentation function for use with the decoder to retrieve metadata
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


    /**
     * Find all memory leak instrumented functions and gather them into sources and sinks
     *
     * @return our memory leak source sink provider
     */
    private static CustomSourceSinkProvider genSourceSinkProvider() {
        CustomSourceSinkProvider ssProvider = new CustomSourceSinkProvider();

        // get all instrumented functions where a variable is set to null and add them as sinks
        ArrayList<SootMethod> nullSets = getNullSetSinkMethods();
        for (SootMethod nullSet: nullSets) {
            ssProvider.addSinkMethod(nullSet);
        }

        // get all instrumented functions where a variable is set to non-null and add them as sources
        for (SootMethod m: getSetSinkMethods()) {
            ssProvider.addSourceMethod(m);
        }

        return ssProvider;
    }

    /**
     * Find all resource leak instrumented functions and gather them into sources and sinks
     *
     * @return our resource leak source sink provider
     */
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

    // MEMORY LEAKS: Traverse callgraph for instrumented null set functions
    private static ArrayList<SootMethod> getNullSetSinkMethods() {
        CallGraph cg = Scene.v().getCallGraph();
        ArrayList<SootMethod> nullSetMethods = new ArrayList<>();

        for (Edge e : cg) {
            if (e.tgt().getName().contains(Instrument.NULLIFY_STATIC_VAR)) {
                nullSetMethods.add(e.tgt());
            }
        }
        return nullSetMethods;
    }

    // MEMORY LEAKS: Traverse callgraph for instrumented set functions
    private static ArrayList<SootMethod> getSetSinkMethods() {
        CallGraph cg = Scene.v().getCallGraph();
        ArrayList<SootMethod> setMethods = new ArrayList<>();

        for (Edge e : cg) {
            if (e.tgt().getName().contains(Instrument.SET_STATIC_VAR)) {
                setMethods.add(e.tgt());
            }
        }
        return setMethods;
    }

    // RESOURCE LEAKS: Traverse callgraph for instrumented resource allocation functions
    private static ArrayList<SootMethod> getResourceSourceMethods() {
        CallGraph cg = Scene.v().getCallGraph();
        ArrayList<SootMethod> setMethods = new ArrayList<>();

        for (Edge e : cg) {
            if (e.tgt().getName().contains(Instrument.OPEN_RESOURCE)) {
                setMethods.add(e.tgt());
            }
        }
        return setMethods;
    }

    // RESOURCE LEAKS: Traverse callgraph for instrumented resource deallocation functions
    private static ArrayList<SootMethod> getResourceSinkMethods() {
        CallGraph cg = Scene.v().getCallGraph();
        ArrayList<SootMethod> setMethods = new ArrayList<>();

        for (Edge e : cg) {
            if (e.tgt().getName().contains(Instrument.CLOSE_RESOURCE)) {
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

class CliOptions {
    public String apkPath;
    public String instrumentedApkPath;
    public String platformPath;
    public boolean resourceMode;
    public int timeout_seconds;
    public int timeout_minutes;

    public CliOptions(String a, String p, boolean r, int timeout_m) throws ParseException {
        if(!Files.isReadable(Paths.get(a)))
            throw new ParseException("APK file does not exist!");
        if(!Files.isDirectory(Paths.get(p)))
            throw new ParseException("Android platforms path does not exist!");

        apkPath = a;
        instrumentedApkPath = buildOutputPath(a);
        platformPath = p;
        resourceMode = r;
        timeout_minutes = timeout_m;
        timeout_seconds = timeout_m * 60;
    }

    private static String buildOutputPath(String path) {
        String [] apkFilePieces = path.split("/");
        String filename = apkFilePieces[apkFilePieces.length - 1];

        return "./sootOutput/" + filename;
    }
}

