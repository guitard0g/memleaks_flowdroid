package com.guitard0g.dataflow_analysis;

import soot.SootMethod;

import java.util.ArrayList;

public class AllocationPair {
    public String opener;
    public String closer;
    public String className;
    public String openKey;
    public String closeKey;
    private ArrayList<SootMethod> openerCallingMethods;
    private ArrayList<SootMethod> closerCallingMethods;

    public AllocationPair(String line) throws InvalidResourceStringException {
        String pieces[] = line.split(" ## ");
        if (pieces.length != 3) {
            throw new InvalidResourceStringException("Could not parse line: " + line);
        } else {
            String className = pieces[0];
            String opener = pieces[1];
            String closer = pieces[2];
            this.opener = opener;
            this.closer = closer;
            this.className = className;
            this.openKey = AllocationPair.getKey(className, opener);
            this.closeKey = AllocationPair.getKey(className, closer);

            this.openerCallingMethods = new ArrayList<>();
            this.closerCallingMethods = new ArrayList<>();
        }
    }

    public void addCallingMethod(SootMethod mCaller, SootMethod m) {
        if (m.getName().equals(this.opener)) {
            this.openerCallingMethods.add(mCaller);
        } else {
            this.closerCallingMethods.add(mCaller);
        }
    }

    public ArrayList<SootMethod> getOpenerCallingMethods() {
        return this.openerCallingMethods;
    }

    public ArrayList<SootMethod> getCloserCallingMethods() {
        return this.closerCallingMethods;
    }

    public static String getKey(String className, String method) {
        StringBuilder sb = new StringBuilder();
        sb.append(className);
        sb.append(',');
        sb.append(method);
        return sb.toString();
    }

    public static String getFullKey(String className, String a, String b, AllocType allocType) {
        String opener;
        String closer;
        if (allocType == AllocType.OPENER) {
            opener = a;
            closer = b;
        } else {
            opener = b;
            closer = a;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(className);
        sb.append(" ## ");
        sb.append(opener);
        sb.append(" ## ");
        sb.append(closer);
        return sb.toString();
    }

    static class InvalidResourceStringException extends Exception {
        public InvalidResourceStringException(String errorMessage) {
            super(errorMessage);
        }
    }
}
