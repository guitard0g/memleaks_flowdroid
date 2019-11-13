package com.guitard0g.dataflow_analysis;

import fj.P;
import org.xmlpull.v1.XmlPullParserException;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.infoflow.aliasing.Aliasing;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.results.DataFlowResult;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.solver.cfg.InfoflowCFG;
import soot.jimple.infoflow.sourcesSinks.definitions.ISourceSinkDefinitionProvider;
import soot.jimple.infoflow.sourcesSinks.definitions.SourceSinkDefinition;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.callgraph.ReachableMethods;
import soot.options.Options;
import soot.toolkits.graph.DirectedGraph;

import java.io.*;
import java.util.*;

import static soot.SootClass.BODIES;

public class App
{
    public static void main(String[] args) throws IOException, XmlPullParserException {
        List<String> resourcePairs = App.getResourcePairs();
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


        // Iterate over the callgraph
        for (Iterator<Edge> edgeIt = cg.iterator(); edgeIt.hasNext(); ) {
            Edge edge = edgeIt.next();

            SootMethod smSrc = edge.src();
            Unit uSrc = edge.srcStmt();
            SootMethod smDest = edge.tgt();
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

    private static List<String> getResourcePairs() {
        List<String> list = new ArrayList<String>();
        File file = new File("pairs.txt");
        BufferedReader reader = null;

        try {
            reader = new BufferedReader(new FileReader(file));
            String text = null;

            while ((text = reader.readLine()) != null) {
                list.add(text);
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
        return list;
    }
}
