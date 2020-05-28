#!/usr/bin/env bash
export JAVA_PROGRAM_ARGS=`echo "$@"`
mvn compile exec:java -Dexec.mainClass="com.guitard0g.dataflow_analysis.App" -Dexec.args="$JAVA_PROGRAM_ARGS"
