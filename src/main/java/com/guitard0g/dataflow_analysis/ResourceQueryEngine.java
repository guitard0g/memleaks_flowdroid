package com.guitard0g.dataflow_analysis;

import soot.SootMethod;

import java.util.HashMap;

enum AllocType {
    OPENER, CLOSER, NONE;
}

public class ResourceQueryEngine {
    public HashMap<String, AllocationPair> pairMap;
    public HashMap<String, String> openToCloseMap;
    public HashMap<String, String> closeToOpenMap;
    public HashMap<SootMethod, String> keyMap;
    public HashMap<SootMethod, String> matchingKeyMap;

    public ResourceQueryEngine() {
        pairMap = new HashMap<>();
        openToCloseMap = new HashMap<>();
        closeToOpenMap = new HashMap<>();
        keyMap = new HashMap<>();
        matchingKeyMap = new HashMap<>();
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

    public String getMatchingKey(SootMethod m) {
        String matchingKey;
        if (matchingKeyMap.containsKey(m)) {
            matchingKey = matchingKeyMap.get(m);
        } else {
            String key = getKey(m);
            String mClassName = m.getDeclaringClass().getName();
            if (openToCloseMap.containsKey(key)) {
                // m is an opener
                matchingKey = AllocationPair.getKey(mClassName, openToCloseMap.get(key));
            } else if (closeToOpenMap.containsKey(key)) {
                // m is a closer
                matchingKey = AllocationPair.getKey(mClassName, closeToOpenMap.get(key));
            } else {
                // impossible
                matchingKey = null;
            }
            matchingKeyMap.put(m, matchingKey);
        }
        return matchingKey;
    }

    public AllocationPair getAllocationPair(SootMethod m) {
        String key = getKey(m);
        String mName = m.getName();
        String mClassName = m.getDeclaringClass().getName();
        String mMatchingName = null;

        if (openToCloseMap.containsKey(key)) {
            // m is an opener
            mMatchingName = openToCloseMap.get(key);
        } else if (closeToOpenMap.containsKey(key)) {
            // m is a closer
            mMatchingName = closeToOpenMap.get(key);
        }

        return pairMap.get(AllocationPair.getFullKey(mClassName, mName, mMatchingName));
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
