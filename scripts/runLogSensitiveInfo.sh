#!/bin/bash
ROOT=/home/hcai/
curpath=`pwd`

#:$ROOT/libs/rt.jar
MAINCP=".:$ROOT/libs/polyglot.jar:$ROOT/libs/sootclasses-trunk.jar:$ROOT/libs/jasminclasses-trunk.jar:$ROOT/workspace/duafdroid/bin:$ROOT/workspace/droidfax/bin:$ROOT/libs/java_cup.jar"

export SIREUM_HOME=/home/hcai/Sireum

#for module in `ls /home/hcai/workspace_sireum/amandroid`
for module in /home/hcai/workspace_sireum/amandroid/*
do
	#module=`readlink -f $module`
	#echo "module="$module
	if [ ! -d "$module" ];then 
		continue
	fi
	MAINCP=$MAINCP:$module/bin
	if [ ! -d "$module"/libs ];then 
		continue
	fi
	for i in $module/libs/*.jar;
	do
		MAINCP=$MAINCP:$i
	done
done
for j in /home/hcai/Sireum/lib/*.jar
do
	MAINCP=$MAINCP:$j
done

starttime=`date +%s%N | cut -b1-13`

srcpath=/home/hcai/Downloads/DroidBench-master/testedapk
destpath=$curpath/amandroidResults
mkdir -p $destpath
scala -J-Xmx2g -classpath ${MAINCP} org.sireum.amandroid.run.security.LogSensitiveInfo_run \
	$srcpath \
	$destpath 

stoptime=`date +%s%N | cut -b1-13`
echo "time elapsed: " `expr $stoptime - $starttime` milliseconds
exit 0

# hcai vim :set ts=4 tw=4 sws=4
