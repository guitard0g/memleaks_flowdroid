#!/usr/bin/env bash
export PROGRAM_ARGS=`echo "$@"`
python3 experiment/resource_leaks/run_experiment.py $PROGRAM_ARGS
