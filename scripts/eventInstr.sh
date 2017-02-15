#!/bin/bash
if [ $# -lt 1 ];then
	echo "Usage: $0 apk-file"
	exit 1
fi

apkfile=$1

ROOT=/home/hcai/
subjectloc=`pwd`

OUTDIR=${2:-"$subjectloc/event.instrumented/"}

MAINCP="$ROOT/libs/rt.jar:$ROOT/libs/polyglot.jar:$ROOT/libs/soot-trunk.jar:$ROOT/workspace/duafdroid/bin:$ROOT/workspace/iac/bin:$ROOT/libs/java_cup.jar"

SOOTCP="$ROOT/workspace/iac/bin:/home/hcai/Android/Sdk/platforms/android-21/android.jar"

for i in $ROOT/libs/*.jar;
do
	#SOOTCP=$SOOTCP:$i
    MAINCP=$MAINCP:$i
done

# get the apk file name without prefixing path and suffixing extension
suffix=${apkfile##*/}
suffix=${suffix%.*}

LOGDIR=out-dynInstr-event
mkdir -p $LOGDIR
logout=$LOGDIR/instr-$suffix.out
logerr=$LOGDIR/instr-$suffix.err

mkdir -p $OUTDIR

starttime=`date +%s%N | cut -b1-13`

	#-allowphantom \
   	#-duaverbose \
	#-dumpFunctionList \
	#-statUncaught \
    #-f c \
    #--nostatic --aplength 1 --aliasflowins --nocallbacks --layoutmode none --noarraysize --nopaths --pathalgo sourcesonly \
    #-android-jars $ROOT/libs/backup/android.jar \
    #-src-prec apk \
    #-f J \
    #-debug \
    #-force-android-jar $ROOT/libs/backup/android.jar \
	#-slicectxinsens \
	#-nophantom \
	#-p wjtp enabled:true -p wjpp enabled:false \
    #
	#-instr3rdparty \
	#-dumpJimple \
cmd="java -Xmx4g -ea -cp ${MAINCP} eventTracker.sceneInstr \
	-w -cp $SOOTCP -p cg verbose:false,implicit-entry:true \
	-p cg.spark verbose:false,on-fly-cg:true,rta:false \
	-d $OUTDIR \
    -debug \
	-catcallback /home/hcai/libs/catCallbacks.txt \
	-instr3rdparty \
    -instrlifecycle \
	-process-dir $apkfile"

($cmd | tee $logout) 3>&1 1>&2 2>&3 | tee $logerr
#${cmd} 2>&1 | tee $logout

stoptime=`date +%s%N | cut -b1-13`
echo "StaticAnalysisTime for $suffix elapsed: " `expr $stoptime - $starttime` milliseconds
echo "static analysis finished."

echo "chapple" | ./signandalign.sh $OUTDIR/${suffix}.apk >/dev/null 
exit 0


# hcai vim :set ts=4 tw=4 sws=4

