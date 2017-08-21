#!/bin/bash
if [ $# -lt 2 ];then
	echo "Usage: $0 apk-file trace-file"
	exit 1
fi

apkfile=$1
tracefile=$2

ROOT=/home/hcai/
subjectloc=`pwd`

OUTDIR=${2:-"$subjectloc/cg.instrumented/"}

MAINCP="$ROOT/libs/rt.jar:$ROOT/libs/polyglot.jar:$ROOT/libs/soot-trunk.jar:$ROOT/workspace/duafdroid/bin:$ROOT/workspace/droidfax/bin:$ROOT/libs/java_cup.jar"

SOOTCP="$ROOT/workspace/droidfax/bin:/home/hcai/Android/Sdk/platforms/android-23/android.jar"

for i in $ROOT/libs/*.jar;
do
	#SOOTCP=$SOOTCP:$i
    MAINCP=$MAINCP:$i
done

starttime=`date +%s%N | cut -b1-13`

	#-debug \
	#-featuresOnly \
java -Xmx4g -ea -cp ${MAINCP} reporters.generalReport \
	-w -cp $SOOTCP -p cg verbose:false,implicit-entry:true \
	-p cg.spark verbose:false,on-fly-cg:true,rta:false \
	-d $OUTDIR \
	-process-dir $apkfile \
	-trace $tracefile

stoptime=`date +%s%N | cut -b1-13`

echo "Time elapsed: " `expr $stoptime - $starttime` milliseconds
exit 0

# hcai vim :set ts=4 tw=4 sws=4

