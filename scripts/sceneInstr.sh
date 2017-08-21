#!/bin/bash
if [ $# -lt 1 ];then
	echo "Usage: $0 apk-file"
	exit 1
fi

apkfile=$1

ROOT=/home/hcai/
subjectloc=`pwd`

MAINCP=".:$ROOT/libs/rt.jar:$ROOT/libs/soot-trunk.jar:$ROOT/workspace/duafdroid/bin:$ROOT/workspace/droidfax/bin:$ROOT/libs/java_cup.jar"

SOOTCP=".:$ROOT/workspace/droidfax/bin"

for i in $ROOT/libs/*.jar;
do
	#SOOTCP=$SOOTCP:$i
    MAINCP=$MAINCP:$i
done

suffix=${apkfile##*/}
suffix=${suffix%%.*}

LOGDIR=out-dyndroidfaxInstr-scene
mkdir -p $LOGDIR
logout=$LOGDIR/instr-$suffix.out
logerr=$LOGDIR/instr-$suffix.err

OUTDIR=$subjectloc/scene.instrumented/
mkdir -p $OUTDIR

starttime=`date +%s%N | cut -b1-13`

	#-allowphantom \
   	#-duaverbose \
	#-dumpFunctionList \
	#-statUncaught \
	#-main-class $DRIVERCLASS \
	#-entry:$DRIVERCLASS \
	#-main-class org.apache.zookeeper.util.FatJarMain \
	#-entry:org.apache.zookeeper.util.FatJarMain \
	#-process-dir $subjectloc/build/contrib/fatjar/classes \
    #-f c \
    #--nostatic --aplength 1 --aliasflowins --nocallbacks --layoutmode none --noarraysize --nopaths --pathalgo sourcesonly \
    #-android-jars $ROOT/libs/backup/android.jar \
    #-src-prec apk \
    #-f J \
java -Xmx4g -ea -cp ${MAINCP} intentTracker.sceneInstr\
	-w -cp $SOOTCP -p cg verbose:false,implicit-entry:true \
	-p cg.spark verbose:false,on-fly-cg:true,rta:false \
    -debug \
	-d $OUTDIR \
    -force-android-jar $ROOT/libs/backup/android-8.jar \
	-dumpJimple \
	-perfDUAF \
	-brinstr:off -duainstr:off \
	-allowphantom \
	-slicectxinsens \
	-process-dir $subjectloc/$apkfile \
	#1> $logout 2> $logerr

stoptime=`date +%s%N | cut -b1-13`
echo "StaticAnalysisTime for $suffix elapsed: " `expr $stoptime - $starttime` milliseconds
echo "static analysis finished."
exit 0


# hcai vim :set ts=4 tw=4 sws=4

