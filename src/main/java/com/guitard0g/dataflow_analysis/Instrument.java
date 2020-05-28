package com.guitard0g.dataflow_analysis;

import soot.*;
import soot.jimple.*;
import soot.jimple.internal.JReturnStmt;
import soot.jimple.internal.JimpleLocal;

import java.util.*;
import java.util.function.Function;


public class Instrument {
    // Metadata hashmap for storing info about instrumented functions
    public static HashMap<Integer, DummyCallInfo> keyToInfoDecoder = new HashMap<>();
    // stores resources that we see used so that we know which ones to instrument close functions for
    static HashSet<SootClass> usedResources = new HashSet<>();
    // keep a count of the number of thread/async related bugs for logging
    static int threadBugCount = 0;
    // keeps track of resource open methods
    static HashSet<SootMethod> resourceOpens = new HashSet<>();
    // whether or not we are instrumenting resources
    static boolean resMode = false;


    // set of all context containers that can qualify for memory leaks
    static HashSet<SootClass> contextContainers = new HashSet<>();
    // prefixes for function names of API functions that be resource openers
    static final HashSet<String> openers = new HashSet<>(Arrays.asList(new String[]{"start", "obtain", "request", "lock", "open", "register", "acquire", "vibrate", "enable", "<init>"}));
    // prefixes for function names of API functions that be resource closers
    static final HashSet<String> closers = new HashSet<>(Arrays.asList(new String[]{"end","abandon","cancel","clear","close","disable","finish","recycle","release","remove","stop","unload","unlock","unmount","unregister"}));
    // set of all classes we will consider as resources
    static final HashSet<String> resClasses = new HashSet<>(Arrays.asList(
            new String[]{
//                    "AudioManager",
//                    "AudioRecorder",
//                    "android.media.MediaPlayer",
//                    "android.hardware.Camera",
//                    "SensorManager",
//                    "LocationManager",
//                    "android.os.PowerManager.WakeLock",
//                    "android.net.wifi.WifiManager.WifiLock",
//                    "android.location.LocationListener",
//                    "android.hardware.Sensor",
//                    "android.graphics.Bitmap",
//                    "android.os.Binder",
//                    "android.bluetooth.BluetoothAdapter",
//                    "android.media.MediaRecorder",
//                    "android.media.AudioManager",
//                    "android.os.Vibrator",
//                    "android.database.sqlite.SQLiteClosable",
//                    "android.database.sqlite.SQLiteDatabase",
//                    "android.net.http.AndroidHttpClient",
//                    "android.view.MotionEvent",
//                    "android.os.ParcelFileDescriptor",
//                    "android.os.Parcel"
//                    "java.io.InputStream",
//                    "java.io.FileInputStream",
//                    "java.io.FileOutputStream",
//                    "java.io.BufferedReader",
//                    "java.io.FilterOutputStream",
//                    "java.io.FilterInputStream",
//                    "java.io.OutputStream",
                    "android.database.Cursor"
            }));

    // Instrumentation function name constants
    public static final String OPEN_RESOURCE = "__OPEN__RES__";
    public static final String CLOSE_RESOURCE = "__CLOSE__RES__";

    public static final String SET_STATIC_VAR = "__SET__VAR__";
    public static final String NULLIFY_STATIC_VAR = "__NULLIFY__VAR__";

    // List of auto managed resources that we do not need to worry about for leaks
    static final HashSet<String> autoManagedResources = new HashSet<>(Arrays.asList(
            "android.database.sqlite.SQLiteOpenHelper"));

    public static HashMap<Integer, DummyCallInfo> instrument(String sdkPath, String apkPath, boolean resourceMode) {
        resMode = resourceMode;

        // We use the Soot pack manager to add a pass for instrumenting
        PackManager.v().getPack("wjtp").add(new Transform("wjtp.myInstrumenter", new SceneTransformer() {
            // SceneTransformer allows us to look at the entire scene for instrumenting
            // (A "Scene" is the collection of all information about the APK that Soot has most recently analyzed)
            @Override
            protected void internalTransform(String var1, Map<String, String> var2) {
                // Keep track of methods we have seen
                InstrumenterData data = new InstrumenterData();

                // Traverse all classes and calculate which ones are context containers
                gatherContextContainers();

                if (!resourceMode)
                    // If we are considering memory leaks, then analyze all thread classes
                    analyzeThreadWork(data);
                // Analyze openers of resources XOR static variables
                analyzeOpeners(data);
                // Analyze closers of resources XOR static variables
                analyzeClosers(data);

                // This is necessary to make sure we validate all of the classes we have altered
                // add all new methods to their corresponding classes
                for (SootMethod m: data.nullSets.values()) {
                    SootClass c = m.getDeclaringClass();
                    c.validate();
                }
                for (SootMethod m: data.valSets.values()) {
                    SootClass c = m.getDeclaringClass();
                    c.validate();
                }
                for (SootMethod m: data.resourceOpens) {
                    SootClass c = m.getDeclaringClass();
                    c.validate();
                }
                for (SootMethod m: data.resourceCloses) {
                    SootClass c = m.getDeclaringClass();
                    c.validate();
                }
            }
        }));

        // Run the instrumentation
        soot.Main.main(new String[]{"-android-jars", sdkPath, "-process-dir", apkPath});
        // Display thread bug number
        System.out.println("Number of Thread related bugs: " + threadBugCount);

        // clear this so that it doesnt take up heap space
        contextContainers = null;

        // return this as the decoder for our dataflow analysis
        return keyToInfoDecoder;
    }

    /**
     * Traverse the program code for AsyncTasks, ThreadTasks, TimerTasks that can cause a thread to reach a context
     *
     * @param data Metadata for analysis
     */
    public static void analyzeThreadWork(InstrumenterData data) {
        // Traverse all classes
        for(SootClass c: Scene.v().getApplicationClasses()) {
            // Traverse all methods
            for (SootMethod m : c.getMethods()) {
                // Get information about the current method
                CurrentOpenerMethodData mData;
                try {
                    mData = new CurrentOpenerMethodData(m);
                } catch (MalformedMethodException e) {
                    continue;
                }

                // Iterate all units (bytecode instructions)
                //important to use snapshotIterator here
                for(Iterator iter = mData.units.snapshotIterator(); iter.hasNext();) {
                    final Unit u = (Unit)iter.next();

                    // Check the instruction for an object creation (which will be an <init>() invoke statement)
                    u.apply(new AbstractStmtSwitch() {
                        // InvokeStmt = method invocation
                        public void caseInvokeStmt(InvokeStmt stmt) {
                            // check for async tasks
                            caseInvokeAsyncTask(stmt, mData, Instrument::isAsyncTask, "AsyncTask");
                            // check for thread or timer tasks
                            caseInvokeAsyncTask(stmt, mData, Instrument::isThreadOrTimerTask, "ThreadTask/TimerTask");
                        }
                    });
                }
            }
        }
    }

    /**
     * MANY apps have advertisement libraries built in so that the developers can monetize their code.
     * These ad libraries will often have indefinitely running threads that will trigger our leak detector.
     * We want to grep for these ad libraries and ignore them whenever possible because the developer will
     * typically not have control over this code regardless.
     *
     * @param mData method metadata
     * @return whether or not the current method is ad related
     */
    private static boolean isAdRelated(CurrentOpenerMethodData mData) {
        SootClass cls = mData.method.getDeclaringClass();
        String name = cls.getName();
        if (name.contains(".ads.")) {
            return true;
        }
        return false;
    }

    /**
     * There are some classes that will create a resource object but automatically close it for you. We need to
     * identify these so that we do not report their objects as leaks.
     *
     * @param cls SootClass to check for automanaged resource type
     * @return whether or not this is an automanaged resource class
     */
    private static boolean isAutoClosedResource(SootClass cls) {
        return isInterestingClass(cls, c -> autoManagedResources.contains(c.getName()));
    }

    /**
     * Test the current invoke statement to see if it creates a thread-like class and reaches a context container
     *
     * @param stmt The bytecode invoke statement to check
     * @param mData The containing method information
     * @param testFunc The function that checks for the class type to see if it is thread-like
     * @param objectType Logging information for if we find a leak
     */
    public static void caseInvokeAsyncTask(InvokeStmt stmt,
                                           CurrentOpenerMethodData mData,
                                           Function<SootClass, Boolean> testFunc,
                                           String objectType) {
        /*
          If the declaring class is not a context or context container then this is not a leak
          If the method is a library method then we don't check because we only check user-written code
          If the class is Ad related then we don't check.
         */
        if(!isInterestingClass(mData.method.getDeclaringClass(), Instrument::isContextContainer)
                || isLibraryClass(mData.method.getDeclaringClass())
                || stmt.getInvokeExpr().getMethod().getDeclaringClass().isStatic()
                || isAdRelated(mData)
                || !isContextContainer(stmt.getInvokeExpr().getMethod().getDeclaringClass())
        ) {
            return;
        }

        /*
          If the invoke expr is an object instantiation (<init>) and it is instantiating an object that matches our
          test function, then we declare this as a leak and display its information
         */
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

    /**
     * Analyze all allocations. This means opening a resource or setting a static variable
     *
     * @param data Instrumentation metadata that we might add to
     */
    public static void analyzeOpeners(InstrumenterData data) {
        // Iterate over all classes
        for(SootClass c: Scene.v().getApplicationClasses()) {
            // create a copy of the methods because the instrumentation might alter some methods and cause
            // a concurrent modification exception of the for loop
            HashSet<SootMethod> methods = new HashSet<>(c.getMethods());
            // Iterate over all methods
            for (SootMethod m : methods) {
                // Get method metadata we need
                CurrentOpenerMethodData mData;
                try {
                    mData = new CurrentOpenerMethodData(m);
                } catch (MalformedMethodException e) {
                    continue;
                }

                // Iterate over all instructions (units)
                //important to use snapshotIterator here
                for(Iterator iter = mData.units.snapshotIterator(); iter.hasNext();) {
                    final Unit u = (Unit)iter.next();
                    // This switch statement is what applies the instrumentation based on the type of instruction
                    u.apply(new AbstractStmtSwitch() {
                        // This is for identity instructions (assigning a register to a value)
                        public void caseIdentityStmt(IdentityStmt stmt) {
                            openerCaseIdentityStmt(stmt, mData);
                        }

                        // This is for a standard assign statement of a variable
                        public void caseAssignStmt(AssignStmt stmt) {
                            openerCaseAssignStmt(stmt, u, mData, data);
                        }
                    });
                }
            }
        }
    }

    /**
     * Analyze all deallocations or clears. This means closing a resource or setting a static variable to null
     *
     * @param data Instrumentation metadata that we might add to
     */
    public static void analyzeClosers(InstrumenterData data) {
        // Iterate over all classes
        for(SootClass c: Scene.v().getApplicationClasses()) {
            // create a copy of the methods because the instrumentation might alter some methods and cause
            // a concurrent modification exception of the for loop
            HashSet<SootMethod> methods = new HashSet<>(c.getMethods());
            // Iterate over all methods
            for (SootMethod m : methods) {
                // Get method metadata we need
                CurrentCloserMethodData mData;
                try {
                    mData = new CurrentCloserMethodData(m);
                } catch (MalformedMethodException e) {
                    continue;
                }

                // Iterate over all instructions (units)
                //important to use snapshotIterator here
                for(Iterator iter = mData.units.snapshotIterator(); iter.hasNext();) {
                    final Unit u = (Unit)iter.next();
                    // This switch statement is what applies the instrumentation based on the type of instruction
                    u.apply(new AbstractStmtSwitch() {
                        // Instrument variable assign statements
                        public void caseAssignStmt(AssignStmt stmt) {
                            closerCaseAssignStmt(stmt, u, mData, data);
                            // If the right side of the assignment is an invocation, check for resource creation
                            if (resMode && stmt.getRightOp() instanceof InvokeExpr)
                                closerCaseInvokeExpr(stmt.getInvokeExpr(), u, mData, data);
                        }

                        // Instrument a method invocation for resource creation
                        public void caseInvokeStmt(InvokeStmt stmt) {
                            if (resMode)
                                closerCaseInvokeExpr(stmt.getInvokeExpr(), u, mData, data);
                        }
                    });
                }
            }
        }
    }

    /**
     * This is an identity statement so an initial and final value (likely method arg) is being assigned to a register.
     * We need to keep track of the values of each register so that we know what object is being used
     * in method invocations, because method invocations will always act on a register storing an object.
     * Here we set the metadata of the current method to keep track of a mapping of registers to their current values.
     *
     * @param stmt current instruction
     * @param mData method metadata to add the information to
     */
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

            /*
                If this instruction is assigning to a method invocation and that invocation is creating a resource
                then we need to instrument it.
             */
            if (stmt.getRightOp() instanceof InvokeExpr &&
                    isOpener((InvokeExpr) stmt.getRightOp()) &&
                    !resourceOpens.contains(mData.method) &&
                    !mData.skippableInstrs.contains(stmt)
            ) {
                // Only do this if we are looking at resources
                if (!resMode)
                    return;

                // Skip if the class is an autoclosing resource class
                SootClass invokeCls = ((InvokeExpr) stmt.getRightOp()).getMethod().getDeclaringClass();
                if (isAutoClosedResource(invokeCls))
                    return;


                // Add this to our collection of resource openers
                resourceOpens.add(((InvokeExpr)stmt.getRightOp()).getMethod());

                // We need a unique key to decode what method this instrumentation corresponds to.
                // We use the size of the number of instrumentations as the key because this will increment for
                // every new instrumentation.
                int infoKey = keyToInfoDecoder.size();

                // Create our instrumentation dummy method
                SootMethod dummy = createResourceReturnMethod((JimpleLocal)stmt.getLeftOp(), mData.method, infoKey);
                data.resourceOpens.add(dummy);
                // Add the resource type to the collection of used resources so that we know what to look out for
                // in the next pass
                Instrument.usedResources.add(((InvokeExpr) stmt.getRightOp()).getMethod().getDeclaringClass());

                // Add this method to the decoder for use during dataflow analysis
                keyToInfoDecoder.put(infoKey, new DummyCallInfo(stmt.getInvokeExpr().getMethod(), mData.method));


                /*
                    We need to change the bytecode so that we don't alter the behavior of the program but also so that
                    our new instrumented value is being passed along to all of the same places. To achieve this we do
                    the following:
                    // change this
                    $register = ResourceClass.open();

                    // into this
                    $dummyRegister = ResourceClass.open();
                    $register = dummyFunction($dummyRegister);

                    This way we are creating the same resource, but our dummy function is the one assigning the value
                    that the rest of the program will use.
                 */

                // take our original ref and replace it with our new method invocation return val
                Local originalRef = (JimpleLocal)stmt.getLeftOp();
                // make a replacement ref to take the place of the original and add it to the body
                Local replacementRef = Jimple.v().newLocal( "$m1",
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
                for(Trap trap: mData.method.getActiveBody().getTraps()) {
                    if (trap.getEndUnit() == u)
                        trap.setEndUnit(setField);
                }
                mData.method.getActiveBody().validate();
            }
        } else if (stmt.getLeftOp() instanceof StaticFieldRef) {
            // MEMORY LEAKS
            // get the static field that is being assigned
            StaticFieldRef ref = (StaticFieldRef)stmt.getLeftOp();
            SootField f = ref.getField();

            // If this static field reaches a context container, then we need to instrument it
            if (isInterestingAssignment(mData.method, stmt, mData.localAssignments)) {
                // Keep track of the fields we are tracking
                data.fields.add(f);

                // get new unique key for our instrumented dummy function
                int infoKey = keyToInfoDecoder.size();

                // create dummy method that just returns the value of the static variable
                SootMethod dummy = createReturnMethod(f, infoKey);

                // add the new dummy method to the decoder
                keyToInfoDecoder.put(infoKey, new DummyCallInfo(f, mData.method));

                // create a new reference to the static variable
                Local fieldRef = addFieldRef(mData.body, f, "fieldTmpRef");

                // set the new reference to an invocation of our dummy function
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

                for(Trap trap: mData.method.getActiveBody().getTraps()) {
                    if (trap.getEndUnit() == u)
                        trap.setEndUnit(setField);
                }
                mData.method.getActiveBody().validate();
            }
        }
    }

    /**
     * This is a method invocation so we instrument if the base variable is a resource that is being closed
     *
     * @param expr invocation to analyze
     * @param u current full instruction
     * @param mData current method metadata
     * @param data current general instrumentation data
     */
    public static void closerCaseInvokeExpr(InvokeExpr expr,
                                            Unit u,
                                            CurrentCloserMethodData mData,
                                            InstrumenterData data) {

        Value base;
        if (expr instanceof InstanceInvokeExpr && isResCloser(expr)) {
            // Standard case: $register.close() where $register holds a resource object
            base = ((InstanceInvokeExpr)expr).getBase();
        } else if (isSpecialResCloser(expr)){
            // Special case: close($register) where $register holds a resource object and close() is a special case
            // external resource closing method
            base = expr.getArg(0);
        } else {
            // If we don't fit the above cases then back out early
            return;
        }

        // get the unique key for our decoder to store the instrumentation function
        int infoKey = keyToInfoDecoder.size();

        // create dummy method for a resource clear
        SootMethod dummy = createResourceClearMethod(base, mData.method, infoKey);
        // keep track of our resource close methods
        data.resourceCloses.add(dummy);

        // add an entry for this dummy function to our decoder
        keyToInfoDecoder.put(infoKey, new DummyCallInfo(expr.getMethod(), mData.method));

        // create an invocation of our dummy method with the register holding the resource object as the argument, i.e.
        // $register.close()
        // dummy($register)
        Value invocation = Jimple.v().newStaticInvokeExpr(
                dummy.makeRef(),
                base
        );

        // Create a full statement wrapping this invocation
        InvokeStmt invokeStmt = Jimple.v().newInvokeStmt(invocation);

        // add new assign statement
        mData.units.insertAfter(invokeStmt, u);
        for(Trap trap: mData.method.getActiveBody().getTraps()) {
            if (trap.getEndUnit() == u)
                trap.setEndUnit(invokeStmt);
        }
        // validate this method for any mistakes
        mData.method.getActiveBody().validate();
    }

    /**
     * This is an assign statement so we instrument if it is a static variable being set to null
     *
     * @param stmt assignment to analyze
     * @param u current full instruction
     * @param mData current method metadata
     * @param data current general instrumentation data
     */
    public static void closerCaseAssignStmt(AssignStmt stmt,
                                            Unit u,
                                            CurrentCloserMethodData mData,
                                            InstrumenterData data) {

        // If this is assigning to a resource method invocation, we should still instrument it as a resource close
        if (stmt instanceof InvokeStmt &&
                stmt.getInvokeExpr() instanceof InstanceInvokeExpr &&
                isResCloser(stmt.getInvokeExpr())) {

            if (!resMode)
                return;
            SootMethod dummy;
            InstanceInvokeExpr iexpr = (InstanceInvokeExpr)stmt.getInvokeExpr();
            int infoKey = keyToInfoDecoder.size();
            dummy = createResourceClearMethod(iexpr.getBase(), mData.method, infoKey);
            data.resourceCloses.add(dummy);

            keyToInfoDecoder.put(infoKey, new DummyCallInfo(stmt.getInvokeExpr().getMethod(), mData.method));

            Value invocation = Jimple.v().newStaticInvokeExpr(
                    dummy.makeRef(),
                    iexpr.getBase()
            );
            InvokeStmt invokeStmt = Jimple.v().newInvokeStmt(invocation);

            // add new assign statement
            mData.units.insertAfter(invokeStmt, u);
            for(Trap trap: mData.method.getActiveBody().getTraps()) {
                if (trap.getEndUnit() == u)
                    trap.setEndUnit(invokeStmt);
            }
            mData.method.getActiveBody().validate();
        } else if (stmt.getLeftOp() instanceof StaticFieldRef) {
            // We are assigning a static variable

            // get the information about the static variable
            StaticFieldRef ref = (StaticFieldRef)stmt.getLeftOp();
            SootField f = ref.getField();

            // if the static variable reaches a context container and we instrumented an opener for it, and the right
            // side is a null value, then we need to instrument this assignment
            if ((isInterestingField(f) || data.fields.contains(f)) &&
                    stmt.getRightOp() instanceof NullConstant) {
                // get unique key for decoder
                int infoKey = keyToInfoDecoder.size();

                // create our null set dummy method
                SootMethod dummy = createSetNullMethod(f, infoKey);

                // add entry for key mapping to dummy method
                keyToInfoDecoder.put(infoKey, new DummyCallInfo(f, mData.method));

                // create new local register to store the static variable
                Local fieldRef = addFieldRef(mData.body, f, "fieldTmpRef");

                // create new assign statement of this local assigned to the static variable
                AssignStmt assign = Jimple.v().newAssignStmt( fieldRef, Jimple.v().newStaticFieldRef(f.makeRef()) );
                mData.units.insertBefore( assign, u );

                // create new invocation of our dummy method with the new local as the argument
                InvokeStmt invoke = Jimple.v().newInvokeStmt( Jimple.v().newStaticInvokeExpr( dummy.makeRef(), fieldRef ));
                mData.units.insertBefore(invoke, u);

                // check all traps for if we need to change the boundaries
                for(Trap trap: mData.method.getActiveBody().getTraps()) {
                    if (trap.getBeginUnit() == u)
                        trap.setBeginUnit(assign);
                }
                // validate to make sure we didn't mess up
                mData.method.getActiveBody().validate();
            }
        }
    }

    // Add a new local to a method body with the same type as class c
    private static Local addFieldRef(Body body, SootField c, String name)
    {
        Local tmpRef = Jimple.v().newLocal(name, c.getType());
        body.getLocals().add(tmpRef);
        return tmpRef;
    }

    // Create a dummy method that sets field f to null (uses the key for naming the method)
    private static SootMethod createSetNullMethod(SootField f, int key) {
        ArrayList<Type> params = new ArrayList<>();
        params.add(f.getType()); // one parameter of f's type
        Type voidType = VoidType.v();
        // The name will be suffixed with the unique key so that we can retrieve the metadata about this method later
        String name = f.getName() + NULLIFY_STATIC_VAR + key;
        // static
        int modifier = 10; // 1010

        // create the new soot method with this information
        SootMethod m = new SootMethod(name, params, voidType, modifier);

        // create the body
        Body b = createSetNullBody(f);
        // assign the method body
        b.setMethod(m);
        // activate the method body
        m.setActiveBody(b);

        // set SootClass for method
        m.setDeclaringClass(f.getDeclaringClass());
        m.setDeclared(true);

        return m;
    }

    // create the body for assigning field f to null
    private static Body createSetNullBody(SootField f) {
        // get a reference to the static variable
        StaticFieldRef sfr = Jimple.v().newStaticFieldRef(f.makeRef());
        // assign this reference to null
        AssignStmt stmt = Jimple.v().newAssignStmt(sfr, NullConstant.v());
        // create a new method body and add this statement and a void return
        Body b = Jimple.v().newBody();
        b.getUnits().add(stmt);
        b.getUnits().addLast(Jimple.v().newReturnVoidStmt());

        return b;
    }

    // create a method that just returns the current value of the static variable f
    private static SootMethod createReturnMethod(SootField f, int key) {
        ArrayList<Type> params = new ArrayList<>();
        params.add(f.getType()); // one parameter of f's type

        // create the name using the unique key
        String name = f.getName() + SET_STATIC_VAR + key;
        int modifier = 9;

        // create the new method for our dummy
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


    // create the body for returning the static variable
    private static Body createReturnBody(SootField f) {
        Body b = Jimple.v().newBody();

        // create new parameter reference to first method param
        ParameterRef paramRef = Jimple.v().newParameterRef(f.getDeclaringClass().getType(), 0);
        // create new local to store parameter reference
        Local param1 = Jimple.v().newLocal("$r0", f.getDeclaringClass().getType());
        b.getLocals().add(param1);

        // Create assignment of parameter reference to local
        // $r1 = @parameter0: Type
        Stmt assignParam = Jimple.v().newIdentityStmt(param1, paramRef);

        Local fieldRef = addFieldRef(b, f, "fieldTmpRef");
        AssignStmt setField = Jimple.v().newAssignStmt(fieldRef, Jimple.v().newStaticFieldRef(f.makeRef()));

        b.getUnits().addLast(assignParam);
        b.getUnits().addLast(setField);
        b.getUnits().addLast(Jimple.v().newReturnStmt(fieldRef));

        return b;
    }

    // create method for returning the same value that is input as the first method argument
    /*
        public void dummy(Resource x) { return x; }
     */
    private static SootMethod createResourceReturnMethod(JimpleLocal local, SootMethod m, int key) {
        ArrayList<Type> params = new ArrayList<>();
        params.add(local.getType()); // one parameter of f's type

        // name the method using the unique key
        String name = local.getName() + OPEN_RESOURCE + key;
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

    // create the method that will return the value of the argument
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

    // create dummy method that will just take a value as input and do nothing with it (sink method)
    private static SootMethod createResourceClearMethod(Value v, SootMethod m, int key) {
        ArrayList<Type> params = new ArrayList<>();
        params.add(v.getType()); // one parameter of f's type
        Type voidType = VoidType.v();
        String name = v + CLOSE_RESOURCE + key;
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

    // check for if a class is a library class of java or android
    private static boolean isLibraryClass(SootClass cls) {
        if(cls.getName().startsWith("android") ||
                cls.getName().startsWith("java")) {
            return true;
        }
        return false;
    }

    // Check if the field is a context container type
    private static boolean isInterestingField(SootField f) {
        if (!(f.getType() instanceof RefType)) {
            return false;
        }

        SootClass cls = ((RefType) f.getType()).getSootClass();

        return isInterestingClass(cls, Instrument::isContextContainer);
    }

    // Check if the assignment is assigning to a context container
    private static boolean isInterestingAssignment(SootMethod m, AssignStmt stmt, HashMap<JimpleLocal, Value> assignments) {
        // if this is assigning to a local, we ignore it because we will have already seen if that local is a
        // context container before, therefore dataflow analysis will cover this case
        if(!(stmt.getRightOp() instanceof JimpleLocal)) {
            return false;
        }

        // We don't know what value this local holds
        JimpleLocal local = (JimpleLocal)stmt.getRightOp();
        if (!assignments.containsKey(local)) {
            return false;
        }
        Value value = assignments.get(local);

        // if this value doesn't reference an object then it won't be a context container
        if (!(value.getType() instanceof RefType)) {
            return false;
        }

        RefType ref = (RefType)value.getType();
        // check if the type of the right side of the assignment is a context container
        if (isInterestingClass(ref.getSootClass(), Instrument::isContextContainer)) {
            return true;
        }

        // Check for inner class:
        // If this is static or the type of the variable has no outer class, then this is not an inner class we care
        // about
        if (m.isStatic() || !ref.getSootClass().hasOuterClass()) {
            return false;
        }

        // Check if it is an inner class of a context container
        return isInterestingClass(ref.getSootClass().getOuterClass(), Instrument::isContextContainer);
    }

    // Generic function to see if this class or any class in its inheritance hierarchy matches the given test function
    private static boolean isInterestingClass(SootClass cls, Function<SootClass, Boolean> isInterestingFunc) {
        // check base class
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

    // check if this class is a context container
    private static boolean isContextContainer(SootClass cls) {
        return contextContainers.contains(cls);
    }

    // check if this class is an AsyncTask
    private static boolean isAsyncTask(SootClass cls) {
        String name = cls.getName();
        if ( name.equals("android.os.AsyncTask")) {
            return true;
        }
        return false;
    }

    // check if this class is a Thread or Timer Task
    private static boolean isThreadOrTimerTask(SootClass cls) {
        String name = cls.getName();
        if ( name.equals("java.lang.Thread") ||
                name.equals("java.util.TimerTask")) {
            return true;
        }
        return false;
    }

    // Check if the type is a resource
    private static boolean isResourceType(Type t) {
        return resClasses.contains(t.toString());
    }

    // Check if this is a resource class
    private static boolean isResourceClass(SootClass cls) {
        if (resClasses.contains(cls.getName()))
            return true;
        for (String resClass: resClasses) {
            if (isInterestingClass(cls, (SootClass sc)->sc.getName().contains(resClass)))
                return true;
        }
        return false;
    }

    // These are special case closers that actually cause a resource to be automatically managed. If a resource is
    // given to one of these methods as the first argument then it is automatically managed and properly closed
    private static boolean isSpecialResCloser(InvokeExpr iexpr) {
        if (iexpr.getMethod().getName().contains("startManagingCursor"))
            return true;
        if (isInterestingClass(
                iexpr.getMethod().getDeclaringClass(),
                cls -> cls.getName().equals("android.content.ContentQueryMap")) &&
                iexpr.getMethod().getName().equals("<init>")
        ) {
            return true;
        }
        return false;
    }

    // Check if this invocation closes a resource
    private static boolean isResCloser(InvokeExpr iexpr) {
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

    // Check if this invocation opens a resource
    private static boolean isOpener(InvokeExpr iexpr) {
        Type returnType = iexpr.getMethod().getReturnType();
        if (
                iexpr.getMethod().getDeclaringClass().isApplicationClass() ||
                !isResourceType(returnType)) {
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

    // check if the field touches a context
    private static boolean isContextField(SootField f, HashSet<SootClass> currContainers) {
        SootClass typeClass = Scene.v().getSootClassUnsafe(f.getType().toString(), false);
        if (typeClass != null &&
                isInterestingClass(typeClass, cls -> currContainers.contains(cls)))
            return true;
        return false;
    }

    // check if the method m accepts a context container as an argument
    private static boolean hasContextParam(SootMethod m, HashSet<SootClass> currContainers) {
        for (Type t: m.getParameterTypes()) {
            SootClass typeClass = Scene.v().getSootClassUnsafe(t.toString(), false);
            if (typeClass != null &&
                    isInterestingClass(typeClass, cls -> currContainers.contains(cls)))
                return true;
        }
        return false;
    }

    // Go through all fields that can hold context containers
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

    // Go through all classes that can be context containers
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

    // gather all context containers
    private static void gatherContextContainers() {
        contextContainers = gatherContextContainersC();
        contextContainers.addAll(gatherContextContainersF());
    }

    // get constructors for a class
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
    public HashSet<Unit> skippableInstrs;

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
        fillSkippableInstrs();
    }


    private void fillSkippableInstrs() {
        this.skippableInstrs = new HashSet<>();
        HashSet<Unit> skips = new HashSet<>();
        HashSet<Value> rets = new HashSet<>();
        for(Iterator iter = this.units.snapshotIterator(); iter.hasNext();) {
            final Unit u = (Unit)iter.next();
            if (u instanceof JReturnStmt) {
                JReturnStmt ret = (JReturnStmt)u;
                if (ret.getOp() instanceof JimpleLocal)
                    rets.add(ret.getOp());
            }
        }

        for(Iterator iter = this.units.snapshotIterator(); iter.hasNext();) {
            final Unit u = (Unit) iter.next();
            if (u instanceof AssignStmt) {
                if (rets.contains(((AssignStmt)u).getLeftOp()))
                    skips.add(u);
            }
        }

        this.skippableInstrs = skips;
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
