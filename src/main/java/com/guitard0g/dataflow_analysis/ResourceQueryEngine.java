package com.guitard0g.dataflow_analysis;

import fj.Hash;
import soot.SootMethod;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

enum AllocType {
    OPENER, CLOSER, NONE;
}

public class ResourceQueryEngine {
    public HashMap<String, AllocationPair> pairMap;
    public HashMap<String, HashSet<String>> openToCloseMap;
    public HashMap<String, HashSet<String>> closeToOpenMap;
    public HashMap<SootMethod, String> keyMap;
    public HashMap<SootMethod, String> matchingKeyMap;

    public ResourceQueryEngine() {
        pairMap = new HashMap<>();
        openToCloseMap = new HashMap<>();
        closeToOpenMap = new HashMap<>();
        keyMap = new HashMap<>();
        matchingKeyMap = new HashMap<>();
    }

    public void putCloseToOpenMap(String closeKey, String opener) {
        this.putInMapMap(closeKey, opener, this.closeToOpenMap);
    }

    public void putOpenToCloseMap(String openKey, String closer) {
        this.putInMapMap(openKey, closer, this.openToCloseMap);
    }

    private void putInMapMap(String key, String val, HashMap<String, HashSet<String>> targetMap) {
        HashSet<String> valSet;
        if (!targetMap.containsKey(key)) {
            valSet = new HashSet<>();
            targetMap.put(key, valSet);
        } else {
            valSet = targetMap.get(key);
        }
        valSet.add(val);
    }


    public String getKey(SootMethod m) {
        String key;
        if (keyMap.containsKey(m)) {
            key = keyMap.get(m);
        } else {
            String mName = m.getName();
            String mClassName = m.getDeclaringClass().getName();
            key = AllocationPair.getKey(mClassName, mName);
            keyMap.put(m, key);
        }
        return key;
    }

    private ArrayList<String> getMatchingNames(SootMethod m) {
        ArrayList<String> matchingNames = new ArrayList<>();
        String key = getKey(m);
        final HashMap<String, HashSet<String>> mMap;

        if (openToCloseMap.containsKey(key)) {
            // m is an opener
            mMap = this.openToCloseMap;
        } else if (closeToOpenMap.containsKey(key)) {
            // m is a closer
            mMap = this.closeToOpenMap;
        } else {
            // impossible
            return null;
        }

        matchingNames.addAll(mMap.get(key));
        return matchingNames;
    }

    public ArrayList<String> getMatchingKeys(SootMethod m) {
        ArrayList<String> matchingNames = this.getMatchingNames(m);
        if (matchingNames == null) {
            return null;
        }

        ArrayList<String> matchingKeys = new ArrayList<>();
        final String mClassName = m.getDeclaringClass().getName();

        matchingNames.stream()
                .map(matchingName -> AllocationPair.getKey(mClassName, matchingName))
                .forEach(matchingKeys::add);

        return matchingKeys;
    }

    public ArrayList<AllocationPair> getAllocationPairs(SootMethod m) {
        ArrayList<String> matchingNames = this.getMatchingNames(m);
        if (matchingNames == null) {
            return null;
        }

        String mName = m.getName();
        String mClassName = m.getDeclaringClass().getName();
        ArrayList<AllocationPair> allocationPairs = new ArrayList<>();
        AllocType allocType = this.getAllocType(m);

        matchingNames.stream()
                .map(matchingName -> AllocationPair.getFullKey(mClassName, mName, matchingName, allocType))
                .map(fullKey -> this.pairMap.get(fullKey))
                .forEach(allocationPairs::add);
        return allocationPairs;
    }

    public AllocType getAllocType(SootMethod m) {
        String key = getKey(m);

        if (openToCloseMap.containsKey(key)) {
            return AllocType.OPENER;
        } else if (closeToOpenMap.containsKey(key)) {
            return AllocType.CLOSER;
        } else {
            return AllocType.NONE;
        }
    }
}
