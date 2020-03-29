package com.guitard0g.dataflow_analysis;

import java.util.*;

import soot.*;
import soot.jimple.*;
import soot.jimple.internal.JVirtualInvokeExpr;
import soot.jimple.internal.JimpleLocal;
import soot.options.Options;


public class Instrument {
    static HashMap<Integer, DummyCallInfo> keyToInfoDecoder = null;

    static HashSet<String> openers = new HashSet<>(Arrays.asList(new String[]{"start", "request", "lock", "open", "register", "acquire", "vibrate", "enable"}));
    static HashSet<String> closers = new HashSet<>(Arrays.asList(new String[]{"end","abandon","cancel","clear","close","disable","finish","recycle","release","remove","stop","unload","unlock","unmount","unregister"}));


    public static HashMap<Integer, DummyCallInfo> instrument(String sdkPath, String apkPath) {
        //prefer Android APK files// -src-prec apk
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_process_multiple_dex(true);
        Options.v().set_allow_phantom_refs(true);

        Options.v().set_output_format(Options.output_format_dex);
        Options.v().set_force_overwrite(true);
        Options.v().set_whole_program(true);

        PackManager.v().getPack("wjtp").add(new Transform("wjtp.myInstrumenter", new SceneTransformer() {
            @Override
            protected void internalTransform(String var1, Map<String, String> var2) {
                InstrumenterData data = new InstrumenterData();

                analyzeOpeners(data);
                analyzeClosers(data);

                keyToInfoDecoder = data.keyToInfo;

                // add all new methods to their corresponding classes
                for (SootMethod m: data.nullSets.values()) {
                    SootClass c = m.getDeclaringClass();
                    m.setDeclared(false); // clear declared
                    c.addMethod(m); // add method to class
                }
                for (SootMethod m: data.valSets.values()) {
                    SootClass c = m.getDeclaringClass();
                    m.setDeclared(false); // clear declared
                    c.addMethod(m); // add method to class
                }
                for (SootMethod m: data.resourceOpens) {
                    SootClass c = m.getDeclaringClass();
                    m.setDeclared(false); // clear declared
                    c.addMethod(m); // add method to class
                }
                for (SootMethod m: data.resourceCloses) {
                    SootClass c = m.getDeclaringClass();
                    m.setDeclared(false); // clear declared
                    c.addMethod(m); // add method to class
                }
            }


        }));

        soot.Main.main(new String[]{"-android-jars", sdkPath, "-process-dir", apkPath});

        return keyToInfoDecoder;
    }

    public static void analyzeOpeners(InstrumenterData data) {
        for(SootClass c: Scene.v().getApplicationClasses()) {
            for (SootMethod m : c.getMethods()) {
                CurrentOpenerMethodData mData;
                try {
                    mData = new CurrentOpenerMethodData(m);
                } catch (MalformedMethodException e) {
                    continue;
                }

                //important to use snapshotIterator here
                for(Iterator iter = mData.units.snapshotIterator(); iter.hasNext();) {
                    final Unit u = (Unit)iter.next();
                    u.apply(new AbstractStmtSwitch() {
                        public void caseIdentityStmt(IdentityStmt stmt) {
                            openerCaseIdentityStmt(stmt, mData);
                        }

                        public void caseAssignStmt(AssignStmt stmt) {
                            openerCaseAssignStmt(stmt, u, mData, data);
                        }
                    });
                }
            }
        }
    }

    public static void analyzeClosers(InstrumenterData data) {
        for(SootClass c: Scene.v().getApplicationClasses()) {
            for (SootMethod m : c.getMethods()) {
                CurrentCloserMethodData mData;
                try {
                    mData = new CurrentCloserMethodData(m);
                } catch (MalformedMethodException e) {
                    continue;
                }

                //important to use snapshotIterator here
                for(Iterator iter = mData.units.snapshotIterator(); iter.hasNext();) {
                    final Unit u = (Unit)iter.next();
                    u.apply(new AbstractStmtSwitch() {
                        public void caseAssignStmt(AssignStmt stmt) {
                            closerCaseAssignStmt(stmt, u, mData, data);
                        }
                    });
                }
            }
        }
    }

    public static void openerCaseIdentityStmt(IdentityStmt stmt,
                                            CurrentOpenerMethodData mData) {
        if (stmt.getLeftOp() instanceof JimpleLocal) {
            // keep track of local values
            mData.localAssignments.put((JimpleLocal)stmt.getLeftOp(), stmt.getRightOp());
        }
    }

    public static void openerCaseAssignStmt(AssignStmt stmt,
                                            Unit u,
                                            CurrentOpenerMethodData mData,
                                            InstrumenterData data) {
        if (stmt.getLeftOp() instanceof JimpleLocal) {
            // keep track of local values
            mData.localAssignments.put((JimpleLocal)stmt.getLeftOp(), stmt.getRightOp());
            if (stmt.getRightOp() instanceof InvokeExpr && isOpener((InvokeExpr) stmt.getRightOp())) {
                SootMethod dummy;
                // calculate new key for next dummy call info object
                int infoKey = data.resourceOpens.size() + data.resourceCloses.size() + data.nullSets.size() + data.valSets.size();

                dummy = createResourceReturnMethod((JimpleLocal)stmt.getLeftOp(), mData.method, infoKey);
                data.resourceOpens.add(dummy);

                data.keyToInfo.put(infoKey, new DummyCallInfo(null, mData.method));


                // take our original ref and replace it with our new method invocation return val
                Local originalRef = (JimpleLocal)stmt.getLeftOp();
                // make a replacement ref to take the place of the original and add it to the body
                Local replacementRef = Jimple.v().newLocal( originalRef.getName() + "replacementRef",
                        stmt.getLeftOp().getType());
                mData.body.getLocals().add(replacementRef);

                // create method invocation that sets our original ref to our dummy method invocation
                ValueBox invocation = Jimple.v().newInvokeExprBox(Jimple.v().newStaticInvokeExpr(
                        dummy.makeRef(),
                        replacementRef
                ));

                // assign temporary value to original method call
                stmt.setLeftOp(replacementRef);
                // assign our original local to the method invocation
                AssignStmt setField = Jimple.v().newAssignStmt(originalRef, invocation.getValue());

                // add new assign statement
                mData.units.insertAfter(setField, u);

                int test = 0;
            }
        } else if (stmt.getLeftOp() instanceof StaticFieldRef) {
            StaticFieldRef ref = (StaticFieldRef)stmt.getLeftOp();
            SootField f = ref.getField();

            if (isInterestingAssignment(mData.method, stmt, mData.localAssignments)) {
                data.fields.add(f);

                SootMethod dummy;
                if (!data.valSets.containsKey(f)) {
                    // calculate new key for next dummy call info object
                    int infoKey = data.resourceOpens.size() + data.resourceCloses.size() + data.nullSets.size() + data.valSets.size();

                    dummy = createReturnMethod(f, infoKey);
                    data.valSets.put(f, dummy);

                    data.keyToInfo.put(infoKey, new DummyCallInfo(f, mData.method));
                } else {
                    dummy = data.valSets.get(f);
                }

                Local fieldRef = addFieldRef(mData.body, f, "fieldTmpRef");


                ValueBox invocation = Jimple.v().newInvokeExprBox(Jimple.v().newStaticInvokeExpr(
                        dummy.makeRef(),
                        fieldRef
                ));

                // invoke our new method and assign return value to local
                Local fieldRef2 = addFieldRef(mData.body, f, "fieldTmpRef2");
                AssignStmt setTmpField = Jimple.v().newAssignStmt(fieldRef2, invocation.getValue());

                // assign local value to static field
                AssignStmt setField = Jimple.v().newAssignStmt(Jimple.v().newStaticFieldRef(f.makeRef()), fieldRef2);

                // add after in reverse order
                mData.units.insertAfter(setField, u);
                mData.units.insertAfter(setTmpField, u);
                mData.units.insertAfter(Jimple.v().newAssignStmt(fieldRef, Jimple.v().newStaticFieldRef(f.makeRef())), u);
            }
        }
    }

    public static void closerCaseAssignStmt(AssignStmt stmt,
                                            Unit u,
                                            CurrentCloserMethodData mData,
                                            InstrumenterData data) {

        if (stmt instanceof InvokeStmt &&
                stmt.getInvokeExpr() instanceof JVirtualInvokeExpr &&
                isCloser(stmt.getInvokeExpr())) {
            SootMethod dummy;
            JVirtualInvokeExpr iexpr = (JVirtualInvokeExpr)stmt.getInvokeExpr();
            // calculate new key for next dummy call info object
            int infoKey = data.resourceOpens.size() + data.resourceCloses.size() + data.nullSets.size() + data.valSets.size();
            dummy = createResourceClearMethod(iexpr.getBase(), mData.method, infoKey);
            data.resourceCloses.add(dummy);

            data.keyToInfo.put(infoKey, new DummyCallInfo(null, mData.method));


            Value invocation = Jimple.v().newStaticInvokeExpr(
                    dummy.makeRef(),
                    iexpr.getBase()
            );
            InvokeStmt invokeStmt = Jimple.v().newInvokeStmt(invocation);

            // add new assign statement
            mData.units.insertAfter(invokeStmt, u);
        } else if (stmt.getLeftOp() instanceof StaticFieldRef) {
            StaticFieldRef ref = (StaticFieldRef)stmt.getLeftOp();
            SootField f = ref.getField();

            if ((isInterestingField(f) || data.fields.contains(f)) &&
                    stmt.getRightOp() instanceof NullConstant) {
                SootMethod dummy;
                if (!data.nullSets.containsKey(f)) {
                    // calculate new key for next dummy call info object
                    int infoKey = data.resourceOpens.size() + data.resourceCloses.size() + data.nullSets.size() + data.valSets.size();

                    dummy = createSetNullMethod(f, infoKey);
                    data.nullSets.put(f, dummy);

                    data.keyToInfo.put(infoKey, new DummyCallInfo(f, mData.method));
                } else {
                    dummy = data.nullSets.get(f);
                }

                Local fieldRef = addFieldRef(mData.body, f, "fieldTmpRef");

                mData.units.insertBefore(
                        Jimple.v().newAssignStmt(
                                fieldRef,
                                Jimple.v().newStaticFieldRef(f.makeRef())
                        ),
                        u
                );

                mData.units.insertBefore(
                        Jimple.v().newInvokeStmt(
                                Jimple.v().newStaticInvokeExpr(
                                        dummy.makeRef(),
                                        fieldRef
                                )
                        ), u);

            }
        }
    }

    private static Local addFieldRef(Body body, SootField c, String name)
    {
        Local tmpRef = Jimple.v().newLocal(name, c.getType());
        body.getLocals().add(tmpRef);
        return tmpRef;
    }

    private static SootMethod createSetNullMethod(SootField f, int key) {
        ArrayList<Type> params = new ArrayList<>();
        params.add(f.getType()); // one parameter of f's type
        Type voidType = VoidType.v();
        String name = f.getName() + "__SET_NULL__" + key;
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

    private static SootMethod createReturnMethod(SootField f, int key) {
        ArrayList<Type> params = new ArrayList<>();
        params.add(f.getType()); // one parameter of f's type

        String name = f.getName() + "__SET_VAL__" + key;
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

    private static SootMethod createResourceReturnMethod(JimpleLocal local, SootMethod m, int key) {
        ArrayList<Type> params = new ArrayList<>();
        params.add(local.getType()); // one parameter of f's type

        String name = local.getName() + "__OPEN_RES__" + key;
        int modifier = 10; // 1010

        SootMethod mDummy = new SootMethod(name, params, local.getType(), modifier);
        // set SootClass for method
        mDummy.setDeclaringClass(m.getDeclaringClass());
        mDummy.setDeclared(true);

        // create the body
        Body b = createResourceReturnBody(local, mDummy);
        mDummy.setActiveBody(b);

        return mDummy;
    }

    private static Body createResourceReturnBody(JimpleLocal local, SootMethod mDummy) {
        Body b = Jimple.v().newBody();
        b.setMethod(mDummy);
        // create new parameter reference to first method param
        ParameterRef paramRef = Jimple.v().newParameterRef(local.getType(), 0);
        // create new local to store parameter reference
        Local param1 = Jimple.v().newLocal("$r1", local.getType());

        // Create assignment of parameter reference to local
        // $r1 = @parameter0: Type
        Stmt assignParam = Jimple.v().newIdentityStmt(param1, paramRef);

        // return the newly assigned parameter
        Stmt returnStmt = Jimple.v().newReturnStmt(param1);

        b.getLocals().add(param1);
        b.getUnits().addLast(assignParam);
        b.getUnits().addLast(returnStmt);

        return b;
    }

    private static SootMethod createResourceClearMethod(Value v, SootMethod m, int key) {
        ArrayList<Type> params = new ArrayList<>();
        params.add(v.getType()); // one parameter of f's type
        Type voidType = VoidType.v();
        String name = v + "__CLEAR_RES__" + key;
        int modifier = 10; // 1010

        SootMethod mDummy = new SootMethod(name, params, voidType, modifier);

        // create the body
        Body b = Jimple.v().newBody();
        b.setMethod(m);
        mDummy.setActiveBody(b);

        // set SootClass for method
        mDummy.setDeclaringClass(m.getDeclaringClass());
        mDummy.setDeclared(true);

        return mDummy;
    }

    private static boolean isInterestingField(SootField f) {
        if (!(f.getType() instanceof RefType)) {
            return false;
        }

        SootClass cls = ((RefType) f.getType()).getSootClass();

        return isInterestingClass(cls);
    }

    private static boolean isInterestingAssignment(SootMethod m, AssignStmt stmt, HashMap<JimpleLocal, Value> assignments) {
        if(!(stmt.getRightOp() instanceof JimpleLocal)) {
            return false;
        }
        JimpleLocal local = (JimpleLocal)stmt.getRightOp();
        if (!assignments.containsKey(local)) {
            return false;
        }
        Value value = assignments.get(local);

        if (!(value.getType() instanceof RefType)) {
            return false;
        }
        RefType ref = (RefType)value.getType();
        if (isInterestingClass(ref.getSootClass())) {
            return true;
        }

        if (m.isStatic() || !ref.getSootClass().hasOuterClass()) {
            return false;
        }

        return isInterestingClass(ref.getSootClass().getOuterClass());
    }

    private static boolean isInterestingClass(SootClass cls) {
        if (isViewOrActivity(cls))
            return true;

        while (cls.hasSuperclass()) {
            cls = cls.getSuperclass();
            if (isViewOrActivity(cls))
                return true;
        }

        return false;
    }

    private static boolean isViewOrActivity(SootClass cls) {
        String name = cls.getName();
        if ( name.equals("android.view.View") ||
                name.equals("android.app.Activity")) {
            return true;
        }
        return false;
    }

    private static boolean isCloser(InvokeExpr iexpr) {
        if (iexpr.getMethod().getDeclaringClass().isApplicationClass() ||
                !iexpr.getMethod().getReturnType().toString().startsWith("android")) {
            return false;
        }

        String methodName = iexpr.getMethod().getName();
        for (String closer: closers) {
            if (methodName.startsWith(closer)) {
                return true;
            }
        }

        return false;
    }

    private static boolean isOpener(InvokeExpr iexpr) {
        if (iexpr.getMethod().getDeclaringClass().isApplicationClass() ||
                !iexpr.getMethod().getReturnType().toString().startsWith("android")) {
            return false;
        }

        String methodName = iexpr.getMethod().getName();
        for (String opener: openers) {
            if (methodName.startsWith(opener)) {
                return true;
            }
        }

        return false;
    }
}

class DummyCallInfo {
    public SootField f;
    public SootMethod m;

    public DummyCallInfo(SootField f, SootMethod m) {
        this.f = f;
        this.m = m;
    }
}

class InstrumenterData {
    public HashMap<SootField, SootMethod> nullSets;
    public HashMap<SootField, SootMethod> valSets;
    public HashMap<Integer, DummyCallInfo> keyToInfo;
    public HashSet<SootField> fields;
    public HashSet<SootMethod> resourceOpens;
    public HashSet<SootMethod> resourceCloses;

    public InstrumenterData() {
        nullSets = new HashMap<>();
        valSets = new HashMap<>();
        keyToInfo = new HashMap<>();
        fields = new HashSet<>();
        resourceOpens = new HashSet<>();
        resourceCloses = new HashSet<>();
    }
}

class CurrentOpenerMethodData {
    public Body body;
    public SootMethod method;
    public HashMap<JimpleLocal, Value> localAssignments;
    public PatchingChain units;

    public CurrentOpenerMethodData(SootMethod m) {
        if (m.getName().equals("<clinit>")) {
            // Continue if this is a class init because it is
            // not user written so no allocation is being done
            throw new MalformedMethodException();
        }

        if (!m.hasActiveBody()) {
            try {
                m.retrieveActiveBody();
            } catch (Exception ignore) {
                throw new MalformedMethodException();
            }
        }

        this.method = m;
        this.body = m.getActiveBody();
        this.units = this.body.getUnits();
        this.localAssignments = new HashMap<>();
    }
}

class CurrentCloserMethodData {
    public Body body;
    public SootMethod method;
    public PatchingChain units;

    public CurrentCloserMethodData(SootMethod m) {
        if (!m.hasActiveBody()) {
            try {
                m.retrieveActiveBody();
            } catch (Exception ignore) {
                throw new MalformedMethodException();
            }
        }

        this.method = m;
        this.body = m.getActiveBody();
        this.units = this.body.getUnits();
    }
}

class MalformedMethodException extends RuntimeException {
    public MalformedMethodException() {
        super();
    }
}
