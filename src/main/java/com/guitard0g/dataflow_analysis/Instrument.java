package com.guitard0g.dataflow_analysis;

import java.util.*;
import java.util.function.Function;

import soot.*;
import soot.jimple.*;
import soot.jimple.internal.JInvokeStmt;
import soot.jimple.internal.JVirtualInvokeExpr;
import soot.jimple.internal.JimpleLocal;
import soot.options.Options;


public class Instrument {
    static HashMap<Integer, DummyCallInfo> keyToInfoDecoder = null;
    static HashSet<SootClass> usedResources = new HashSet<>();
    static int threadBugCount = 0;
    static HashSet<SootClass> leakyThreadObjects = new HashSet<>();

    static HashSet<SootClass> contextContainers = new HashSet<>();
    static final HashSet<String> openers = new HashSet<>(Arrays.asList(new String[]{"start", "obtain", "request", "lock", "open", "register", "acquire", "vibrate", "enable", "<init>"}));
    static final HashSet<String> closers = new HashSet<>(Arrays.asList(new String[]{"end","abandon","cancel","clear","close","disable","finish","recycle","release","remove","stop","unload","unlock","unmount","unregister"}));
    static final HashSet<String> resClasses = new HashSet<>(Arrays.asList(
            new String[]{"AudioManager",
//                    "AudioRecorder",
                    "android.media.MediaPlayer",
                    "android.hardware.Camera",
//                    "SensorManager",
//                    "LocationManager",
                    "android.os.PowerManager.WakeLock",
                    "android.net.wifi.WifiManager.WifiLock",
                    "android.database.Cursor",
                    "android.location.LocationListener",
//                    "android.hardware.Sensor",
//                    "android.graphics.Bitmap",
//                    "android.os.Binder",
//                    "android.bluetooth.BluetoothAdapter",
//                    "android.media.MediaRecorder",
//                    "android.media.AudioManager",
//                    "android.os.Vibrator",
                    "android.database.sqlite.SQLiteDatabase",
//                    "android.net.http.AndroidHttpClient",
                    "android.view.MotionEvent",
                    "android.os.ParcelFileDescriptor",
                    "android.os.Parcel"
            }));

    public static HashMap<Integer, DummyCallInfo> instrument(String sdkPath, String apkPath, boolean resourceMode) {
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

                gatherContextContainers();

                if (!resourceMode)
                    analyzeThreadWork(data);
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
        System.out.println("Number of Thread related bugs: " + threadBugCount);

        // clear this so that it doesnt take up space
        contextContainers = null;

        return keyToInfoDecoder;
    }

    public static void analyzeThreadWork(InstrumenterData data) {
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
                        public void caseInvokeStmt(InvokeStmt stmt) {
                            caseInvokeAsyncTask(stmt, mData, Instrument::isAsyncTask, "AsyncTask");
                            caseInvokeAsyncTask(stmt, mData, Instrument::isThreadOrTimerTask, "ThreadTask/TimerTask");
//                            caseInvokeAsyncTask(stmt, mData, Instrument::isRunnable, "Runnable");
                        }
                    });
                }
            }
        }
    }

    private static boolean isAdRelated(CurrentOpenerMethodData mData) {
        SootClass cls = mData.method.getDeclaringClass();
        String name = cls.getName();
        if (name.contains(".ads.")) {
            return true;
        }
        return false;
    }

    public static void caseInvokeAsyncTask(InvokeStmt stmt,
                                           CurrentOpenerMethodData mData,
                                           Function<SootClass, Boolean> testFunc,
                                           String objectType) {
        if(!isInterestingClass(mData.method.getDeclaringClass(), Instrument::isViewOrActivity)
                || isLibraryClass(mData.method.getDeclaringClass())
                || stmt.getInvokeExpr().getMethod().getDeclaringClass().isStatic()
                || isAdRelated(mData)
                || !isViewOrActivity(stmt.getInvokeExpr().getMethod().getDeclaringClass())
        ) {
            return;
        }
        if (isInterestingClass(stmt.getInvokeExpr().getMethod().getDeclaringClass(), testFunc) &&
                stmt.getInvokeExpr().getMethod().getName().equals("<init>")) {
            threadBugCount++;

            System.out.println("==========================(" + objectType + ")==============================");
            System.out.println(objectType + " DECLARED INSIDE UI OBJECT (POTENTIAL LEAK): ");
            System.out.println("Bytecode instruction: ");
            System.out.println("\t" + stmt);
            System.out.println("SOURCE: ");
            System.out.println("\t" + mData.method);
            ArrayList<SootMethod> path = App.getMethodPath(mData.method);
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
            HashSet<SootMethod> methods = new HashSet<>(c.getMethods());
            for (SootMethod m : methods) {
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
                            if (stmt.getRightOp() instanceof InvokeExpr)
                                closerCaseInvokeExpr(stmt.getInvokeExpr(), u, mData, data);
                        }

                        public void caseInvokeStmt(InvokeStmt stmt) {
                            closerCaseInvokeExpr(stmt.getInvokeExpr(), u, mData, data);
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
                Instrument.usedResources.add(((InvokeExpr) stmt.getRightOp()).getMethod().getDeclaringClass());

                data.keyToInfo.put(infoKey, new DummyCallInfo(stmt.getInvokeExpr().getMethod(), mData.method));


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

    public static void closerCaseInvokeExpr(InvokeExpr expr,
                                            Unit u,
                                            CurrentCloserMethodData mData,
                                            InstrumenterData data) {

        if (expr instanceof InstanceInvokeExpr && isResCloser(expr)) {
            SootMethod dummy;
            InstanceInvokeExpr iexpr = (InstanceInvokeExpr)expr;
            // calculate new key for next dummy call info object
            int infoKey = data.resourceOpens.size() + data.resourceCloses.size() + data.nullSets.size() + data.valSets.size();
            dummy = createResourceClearMethod(iexpr.getBase(), mData.method, infoKey);
            data.resourceCloses.add(dummy);

            data.keyToInfo.put(infoKey, new DummyCallInfo(expr.getMethod(), mData.method));


            Value invocation = Jimple.v().newStaticInvokeExpr(
                    dummy.makeRef(),
                    iexpr.getBase()
            );
            InvokeStmt invokeStmt = Jimple.v().newInvokeStmt(invocation);

            // add new assign statement
            mData.units.insertAfter(invokeStmt, u);
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

            data.keyToInfo.put(infoKey, new DummyCallInfo(stmt.getInvokeExpr().getMethod(), mData.method));


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

        // create new parameter reference to first method param
        ParameterRef paramRef = Jimple.v().newParameterRef(v.getType(), 0);
        // create new local to store parameter reference
        Local param1 = Jimple.v().newLocal("$r1", v.getType());

        // Create assignment of parameter reference to local
        // $r1 = @parameter0: Type
        Stmt assignParam = Jimple.v().newIdentityStmt(param1, paramRef);

        b.getLocals().add(param1);
        b.getUnits().addLast(assignParam);
        b.getUnits().addLast(Jimple.v().newReturnVoidStmt());

        b.setMethod(m);
        mDummy.setActiveBody(b);

        // set SootClass for method
        mDummy.setDeclaringClass(m.getDeclaringClass());
        mDummy.setDeclared(true);

        return mDummy;
    }

    private static boolean isLibraryClass(SootClass cls) {
        if(cls.getName().startsWith("android") ||
                cls.getName().startsWith("java")) {
            return true;
        }
        return false;
    }

    private static boolean isInterestingField(SootField f) {
        if (!(f.getType() instanceof RefType)) {
            return false;
        }

        SootClass cls = ((RefType) f.getType()).getSootClass();

        return isInterestingClass(cls, Instrument::isViewOrActivity);
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
        if (isInterestingClass(ref.getSootClass(), Instrument::isViewOrActivity)) {
            return true;
        }

        if (m.isStatic() || !ref.getSootClass().hasOuterClass()) {
            return false;
        }

        return isInterestingClass(ref.getSootClass().getOuterClass(), Instrument::isViewOrActivity);
    }

    private static boolean isInterestingClass(SootClass cls, Function<SootClass, Boolean> isInterestingFunc) {
        if (isInterestingFunc.apply(cls))
            return true;
        for(SootClass itf: cls.getInterfaces()) {
            if (isInterestingFunc.apply(itf))
                return true;
        }

        // check inheritance hierarchy
        while (cls.hasSuperclass()) {
            cls = cls.getSuperclass();

            if (isInterestingFunc.apply(cls))
                return true;
            for(SootClass itf: cls.getInterfaces()) {
                if (isInterestingFunc.apply(itf))
                    return true;
            }
        }

        return false;
    }

    private static boolean isViewOrActivity(SootClass cls) {
        return contextContainers.contains(cls);
//        String name = cls.getName();
//        if ( name.equals("android.view.View") ||
//                name.equals("android.app.Activity")) {
//            return true;
//        }
//        return false;
    }

    private static boolean isAsyncTask(SootClass cls) {
        String name = cls.getName();
        if ( name.equals("android.os.AsyncTask")) {
            return true;
        }
        return false;
    }

    private static boolean isRunnable(SootClass cls) {
        String name = cls.getName();
        if ( name.equals("java.lang.Runnable")) {
            return true;
        }
        return false;
    }

    private static boolean isHandler(SootClass cls) {
        String name = cls.getName();
        if ( name.equals("android.os.Handler")) {
            return true;
        }
        return false;
    }

    private static boolean isThreadOrTimerTask(SootClass cls) {
        String name = cls.getName();
        if ( name.equals("java.lang.Thread") ||
                name.equals("java.util.TimerTask")) {
            return true;
        }
        return false;
    }

    private static boolean isResourceType(Type t) {
        if (resClasses.contains(t.toString()))
            return true;
        return false;
    }

    private static boolean isResourceClass(SootClass cls) {
        if (resClasses.contains(cls.getName()))
            return true;
        for (String resClass: resClasses) {
            if (isInterestingClass(cls, (SootClass sc)->sc.getName().contains(resClass)))
                return true;
//            if (cls.getName().contains(resClass))
//                return true;
        }
        return false;
    }

    private static boolean isCloser(InvokeExpr iexpr) {
        if (iexpr.getMethod().getDeclaringClass().isApplicationClass() ||
                !isResourceClass(iexpr.getMethod().getDeclaringClass())) {
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

    private static boolean isResCloser(InvokeExpr iexpr) {
        if (iexpr.getMethod().getDeclaringClass().isApplicationClass() ||
                !isResourceClass(iexpr.getMethod().getDeclaringClass()) ||
                !usedResources.contains(iexpr.getMethod().getDeclaringClass())) {
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
                !isResourceClass(iexpr.getMethod().getDeclaringClass())) {
            return false;
        }

        if(isResourceType(iexpr.getMethod().getReturnType()))
            return true;

        String methodName = iexpr.getMethod().getName();
        for (String opener: openers) {
            if (methodName.startsWith(opener)) {
                return true;
            }
        }

        return false;
    }

    private static boolean isContextField(SootField f, HashSet<SootClass> currContainers) {
        SootClass typeClass = Scene.v().getSootClassUnsafe(f.getType().toString(), false);
        if (typeClass != null &&
                isInterestingClass(typeClass, cls -> currContainers.contains(cls)))
            return true;
        return false;
    }

    private static boolean hasContextParam(SootMethod m, HashSet<SootClass> currContainers) {
        for (Type t: m.getParameterTypes()) {
            SootClass typeClass = Scene.v().getSootClassUnsafe(t.toString(), false);
            if (typeClass != null &&
                    isInterestingClass(typeClass, cls -> currContainers.contains(cls)))
                return true;
        }
        return false;
    }

    private static HashSet<SootClass> gatherContextContainersF() {
        HashSet<SootClass> contextContainers = new HashSet<>();
        SootClass context = Scene.v().getSootClass("android.content.Context");
        contextContainers.add(context);

        // iteratively gather context containers until fixed point
        int prevContainerCount;
        do {
            prevContainerCount = contextContainers.size();

            for(SootClass cls: Scene.v().getClasses()) {
                if (cls.getFields().stream().anyMatch(f -> isContextField(f, contextContainers)) && cls.getInterfaceCount() > 0)
                    contextContainers.add(cls);
            }
        } while (contextContainers.size() != prevContainerCount);

        return contextContainers;
    }

    private static HashSet<SootClass> gatherContextContainersC() {
        HashSet<SootClass> contextContainers = new HashSet<>();
        SootClass context = Scene.v().getSootClass("android.content.Context");
        contextContainers.add(context);

        // iteratively gather context containers until fixed point
        int prevContainerCount;
        do {
            prevContainerCount = contextContainers.size();

            for(SootClass cls: Scene.v().getClasses()) {
                List<SootMethod> constructors = getConstructors(cls);
                if (constructors.stream().anyMatch(f -> hasContextParam(f, contextContainers)))
                    contextContainers.add(cls);
            }
        } while (contextContainers.size() != prevContainerCount);

        return contextContainers;
    }

    private static void gatherContextContainers() {
        contextContainers = gatherContextContainersC();
        contextContainers.addAll(gatherContextContainersF());
    }

    private static List<SootMethod> getConstructors(SootClass cls) {
        ArrayList<SootMethod> constructors = new ArrayList<>();
        for (SootMethod m: cls.getMethods()) {
            if (m.getName().equals("<init>"))
                constructors.add(m);
        }
        return constructors;
    }
}

class DummyCallInfo {
    public SootField f;
    public SootMethod m;
    public SootMethod resOpen;

    public DummyCallInfo(SootField f, SootMethod m) {
        this.f = f;
        this.m = m;
        this.resOpen = null;
    }

    public DummyCallInfo(SootMethod resOpen, SootMethod m) {
        this.f = null;
        this.m = m;
        this.resOpen = resOpen;
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
