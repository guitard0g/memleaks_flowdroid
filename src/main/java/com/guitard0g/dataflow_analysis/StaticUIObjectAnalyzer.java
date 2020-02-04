package com.guitard0g.dataflow_analysis;

import soot.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.util.Chain;

import java.awt.geom.Ellipse2D;
import java.util.*;



public class StaticUIObjectAnalyzer {
    CallGraph cg;

    static String ACTIVITY_CLASS_NAME = "android.app.Activity";
    static String VIEW_CLASS_NAME = "android.view.View";
    private static HashSet<String> uiObjectNames = new HashSet<>(Arrays.asList(new String[]{ACTIVITY_CLASS_NAME, VIEW_CLASS_NAME}));

    public StaticUIObjectAnalyzer() {
        this.cg = Scene.v().getCallGraph();
    }

    public List<SootField> getStaticUIObjectFields() {
        Chain<SootClass> reachableClasses = Scene.v().getClasses();
        ArrayList<SootField> staticUIObjectFields = new ArrayList<>();

        for (SootClass c:
             reachableClasses) {
            for (SootField field: c.getFields()) {
                if (StaticUIObjectAnalyzer.isStaticUIObjectField(field)) {
                    staticUIObjectFields.add(field);
                }
            }
        }

        return staticUIObjectFields;
    }

    private static boolean isStaticUIObjectField(SootField field) {
        if (!field.isStatic()) {
            return false;
        }

        Type t = field.getType();
        if (t instanceof RefType) {
            SootClass typeClass = ((RefType)t).getSootClass();
            while (true) {
                // Climb up the inheritance hierarchy until you find a UI object or get to the root
                if (uiObjectNames.contains(typeClass.getName())) {
                    return true;
                } else if (typeClass.hasSuperclass()) {
                    typeClass = typeClass.getSuperclass();
                } else {
                    // Nothing left to search
                    break;
                }
            }
        }

        return false;
    }
}
