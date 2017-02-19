#!/bin/bash
if [ $# -lt 1 ];then
    echo "Usage: $0 traceFile"
    exit 1
fi

tracefile=$1

MAINCP=".:/etc/alternatives/java_sdk/jre/lib/rt.jar:/home/hcai/workspace/iac/bin:/home/hcai/libs/jgrapht-ext-0.9.1-uber.jar:/home/hcai/libs/android--1/android.jar"

starttime=`date +%s%N | cut -b1-13`

java -Xmx14g -ea -cp ${MAINCP} dynCG.traceStat $tracefile

stoptime=`date +%s%N | cut -b1-13`
echo "time elapsed: " `expr $stoptime - $starttime` milliseconds

exit 0

