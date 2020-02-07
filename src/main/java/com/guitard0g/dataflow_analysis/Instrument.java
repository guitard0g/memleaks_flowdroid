package com.guitard0g.dataflow_analysis;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import soot.*;
import soot.jimple.*;
import soot.options.Options;


public class Instrument {

    public static void instrument(String sdkPath, String apkPath) {
        //prefer Android APK files// -src-prec apk
        Options.v().set_src_prec(Options.src_prec_apk);

        //output as APK, too//-f J
        Options.v().set_output_format(Options.output_format_dex);
        Options.v().set_force_overwrite(true);
        Options.v().set_whole_program(true);

        PackManager.v().getPack("wjtp").add(new Transform("wjtp.myInstrumenter", new SceneTransformer() {
            @Override
            protected void internalTransform(String var1, Map<String, String> var2) {
                HashMap<SootField, SootMethod> nullSetMethods = new HashMap<>();
                HashMap<SootField, SootMethod> valSetMethods = new HashMap<>();
                for(SootClass c: Scene.v().getApplicationClasses()) {
                    for (SootMethod m : c.getMethods()) {
                        if (!m.hasActiveBody()) {
                            try {
                                m.retrieveActiveBody();
                            } catch (Exception ignore) {
                                continue;
                            }
                        }
                        Body b = m.getActiveBody();
                        final PatchingChain units = b.getUnits();
                        //important to use snapshotIterator here
                        for(Iterator iter = units.snapshotIterator(); iter.hasNext();) {
                            final Unit u = (Unit)iter.next();
                            u.apply(new AbstractStmtSwitch() {

                                public void caseAssignStmt(AssignStmt stmt) {
                                    if (stmt.getLeftOp() instanceof StaticFieldRef) {
                                        if (stmt.getRightOp() instanceof NullConstant) {
                                            StaticFieldRef ref = (StaticFieldRef)stmt.getLeftOp();
                                            SootField f = ref.getField();
                                            SootMethod m;
                                            if (!nullSetMethods.containsKey(f)) {
                                                m = createSetNullMethod(f);
                                                nullSetMethods.put(f, m);
                                            } else {
                                                m = nullSetMethods.get(f);
                                            }

                                            Local fieldRef = addFieldRef(b, f, "fieldTmpRef");

                                            units.insertBefore(Jimple.v().newAssignStmt(fieldRef, Jimple.v().newStaticFieldRef(f.makeRef())), u);

                                            units.insertBefore(
                                                    Jimple.v().newInvokeStmt(
                                                            Jimple.v().newStaticInvokeExpr(
                                                                    m.makeRef(),
                                                                    fieldRef
                                                            )
                                                    ), u);

                                        } else {
                                            StaticFieldRef ref = (StaticFieldRef)stmt.getLeftOp();
                                            SootField f = ref.getField();
                                            SootMethod m;
                                            if (!valSetMethods.containsKey(f)) {
                                                m = createReturnMethod(f, valSetMethods.size());
                                                valSetMethods.put(f, m);
                                            } else {
                                                m = valSetMethods.get(f);
                                            }

                                            Local fieldRef = addFieldRef(b, f, "fieldTmpRef");


                                            ValueBox invocation = Jimple.v().newInvokeExprBox(Jimple.v().newStaticInvokeExpr(
                                                    m.makeRef(),
                                                    fieldRef
                                            ));

                                            // invoke our new method and assign return value to local
                                            Local fieldRef2 = addFieldRef(b, f, "fieldTmpRef2");
                                            AssignStmt setTmpField = Jimple.v().newAssignStmt(fieldRef2, invocation.getValue());

                                            // assign local value to static field
                                            AssignStmt setField = Jimple.v().newAssignStmt(Jimple.v().newStaticFieldRef(f.makeRef()), fieldRef2);

                                            // add after in reverse order
                                            units.insertAfter(setField, u);
                                            units.insertAfter(setTmpField, u);
                                            units.insertAfter(Jimple.v().newAssignStmt(fieldRef, Jimple.v().newStaticFieldRef(f.makeRef())), u);
                                        }
                                    }
                                }
                            });
                        }
                    }
                }

                // add all new methods to their corresponding classes
                for (SootMethod m: nullSetMethods.values()) {
                    SootClass c = m.getDeclaringClass();
                    m.setDeclared(false); // clear declared
                    c.addMethod(m); // add method to class
                }
                for (SootMethod m: valSetMethods.values()) {
                    SootClass c = m.getDeclaringClass();
                    m.setDeclared(false); // clear declared
                    c.addMethod(m); // add method to class
                }
            }


        }));

        soot.Main.main(new String[]{"-android-jars", sdkPath, "-process-dir", apkPath});
    }

    private static Local addFieldRef(Body body, SootField c, String name)
    {
        Local tmpRef = Jimple.v().newLocal(name, c.getType());
        body.getLocals().add(tmpRef);
        return tmpRef;
    }

    private static SootMethod createSetNullMethod(SootField f) {
        ArrayList<Type> params = new ArrayList<>();
        params.add(f.getType()); // one parameter of f's type
        Type voidType = VoidType.v();
        String name = f.getName() + "__SET_NULL__";
        int modifier = 10; // 1010

        SootMethod m = new SootMethod(name, params, voidType, modifier);

        // create the body
        Body b = createSetNullBody(f);
        b.setMethod(m);
        m.setActiveBody(b);

        // set SootClass for method
        m.setDeclaringClass(f.getDeclaringClass());
        m.setDeclared(true);

        return m;
    }

    private static Body createSetNullBody(SootField f) {
        StaticFieldRef sfr = Jimple.v().newStaticFieldRef(f.makeRef());
        AssignStmt stmt = Jimple.v().newAssignStmt(sfr, NullConstant.v());
        Body b = Jimple.v().newBody();
        b.getUnits().add(stmt);
        b.getUnits().addLast(Jimple.v().newReturnVoidStmt());

        return b;
    }

    private static SootMethod createReturnMethod(SootField f, int index) {
        ArrayList<Type> params = new ArrayList<>();
        params.add(f.getType()); // one parameter of f's type

        String name = f.getName() + "__SET_VAL__" + index;
        int modifier = 10; // 1010

        SootMethod m = new SootMethod(name, params, f.getType(), modifier);

        // create the body
        Body b = createReturnBody(f);
        b.setMethod(m);
        m.setActiveBody(b);

        // set SootClass for method
        m.setDeclaringClass(f.getDeclaringClass());
        m.setDeclared(true);

        return m;
    }

    private static Body createReturnBody(SootField f) {
        Body b = Jimple.v().newBody();
        Local fieldRef = addFieldRef(b, f, "fieldTmpRef");
        AssignStmt setField = Jimple.v().newAssignStmt(fieldRef, Jimple.v().newStaticFieldRef(f.makeRef()));
        b.getUnits().addLast(setField);
        b.getUnits().addLast(Jimple.v().newReturnStmt(fieldRef));

        return b;
    }
}