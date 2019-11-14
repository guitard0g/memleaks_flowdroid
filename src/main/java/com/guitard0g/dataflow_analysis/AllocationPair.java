package com.guitard0g.dataflow_analysis;

import soot.SootMethod;

public class AllocationPair {
    public String opener;
    public String closer;
    public String className;
    public String openKey;
    public String closeKey;
    public SootMethod openerCallingMethod;

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
            this.openerCallingMethod = null;
        }
    }

    public static String getKey(String className, String method) {
        StringBuilder sb = new StringBuilder();
        sb.append(className);
        sb.append(',');
        sb.append(method);
        return sb.toString();
    }

    public static String getFullKey(String className, String opener, String closer) {
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
