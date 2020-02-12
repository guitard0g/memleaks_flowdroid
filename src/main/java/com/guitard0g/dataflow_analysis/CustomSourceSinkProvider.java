package com.guitard0g.dataflow_analysis;

import fj.Hash;
import soot.SootField;
import soot.SootMethod;
import soot.jimple.infoflow.data.AccessPath;
import soot.jimple.infoflow.data.SootMethodAndClass;
import soot.jimple.infoflow.sourcesSinks.definitions.*;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public class CustomSourceSinkProvider implements ISourceSinkDefinitionProvider {
    private HashMap<String, ISourceSinkDefinition> sourcesAndSinks;
    private HashSet<ISourceSinkDefinition> sources;
    private HashSet<ISourceSinkDefinition> sinks;
    private HashSet<SootMethod> sourceMethods;

    public CustomSourceSinkProvider() {
        sourcesAndSinks = new HashMap<>();
        sources = new HashSet<>();
        sinks = new HashSet<>();
        sourceMethods = new HashSet<>();
    }

    public void addSourceMethod(SootMethod m) {
        HashSet<AccessPathTuple> aps = new HashSet<>();
        aps.add(AccessPathTuple.getBlankSourceTuple());

        HashSet<AccessPathTuple> returnValues = new HashSet<>();
        returnValues.add(AccessPathTuple.getBlankSourceTuple());

        MethodSourceSinkDefinition def = new MethodSourceSinkDefinition(
                new SootMethodAndClass(m),
                aps,
                null,
                returnValues,
                MethodSourceSinkDefinition.CallType.MethodCall);
        sourcesAndSinks.put(m.getSignature(), def);
        sources.add(def);
        sourceMethods.add(m);
    }

    /**
     * Add SootField as a source
     *
     * @param f
     *          The soot field to add as a source
     */
    public void addSourceField(SootField f) {
        HashSet<AccessPathTuple> aps = new HashSet<>();
        aps.add(AccessPathTuple.getBlankSourceTuple());

        String sig = f.getSignature();
        FieldSourceSinkDefinition def = new FieldSourceSinkDefinition(sig, aps);
        sourcesAndSinks.put(sig, def);
        sources.add(def);
    }

    /**
     * Add SootMethod as a sink
     *
     * @param m
     *          The soot method to add as a sink
     */
    public void addSinkMethod(SootMethod m) {
        HashSet<AccessPathTuple> aps = new HashSet<>();
        aps.add(AccessPathTuple.getBlankSinkTuple());

        HashSet[] params = new HashSet[m.getParameterCount()];
        for (int i = 0; i < m.getParameterCount(); i++) {
            HashSet<AccessPathTuple> temp = new HashSet<>();
            temp.add(AccessPathTuple.getBlankSinkTuple());
            params[i] = temp;
        }

        MethodSourceSinkDefinition def = new MethodSourceSinkDefinition(new SootMethodAndClass(m), aps, params, null, MethodSourceSinkDefinition.CallType.MethodCall);
        sourcesAndSinks.put(m.getSignature(), def);
        sinks.add(def);
    }

    public void addSinkField(SootField f) {
        HashSet<AccessPathTuple> aps = new HashSet<>();
        aps.add(AccessPathTuple.getBlankSinkTuple());

        String sig = f.getSignature();
        FieldSourceSinkDefinition def = new FieldSourceSinkDefinition(sig, aps);
        sourcesAndSinks.put(sig, def);
        sinks.add(def);
    }

    public HashSet<SootMethod> getSourceMethods() {
        return sourceMethods;
    }

    public Set<ISourceSinkDefinition> getSources() {
        return sources;
    }

    public Set<ISourceSinkDefinition> getSinks(){
        return sinks;
    }

    public Set<ISourceSinkDefinition> getAllMethods(){
        return new HashSet(sourcesAndSinks.values());
    }
}
