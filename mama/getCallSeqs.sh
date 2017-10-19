#!/bin/bash
if [ $# -lt 1 ];then
	echo "Usage: $0 apk-file"
	exit 1
fi

apkfile=$1

ROOT=/home/hcai/
subjectloc=`pwd`

MAINCP="$ROOT/libs/rt.jar:$ROOT/libs/polyglot.jar:$ROOT/libs/soot-trunk.jar:$ROOT/workspace/duafdroid/bin:$ROOT/workspace/droidfax/bin:$ROOT/libs/java_cup.jar"

for i in $ROOT/libs/*.jar;
do
    MAINCP=$MAINCP:$i
done

# get the apk file name without prefixing path and suffixing extension
suffix=${apkfile##*/}
suffix=${suffix%.*}

LOGDIR=out-dynInstr-cg
mkdir -p $LOGDIR
logout=$LOGDIR/instr-$suffix.out
logerr=$LOGDIR/instr-$suffix.err

starttime=`date +%s%N | cut -b1-13`

    #/home/hcai/Android/Sdk/platforms/android-21/android.jar"
cmd="java -Xmx14g -ea -cp ${MAINCP} dynCG.enumCallSeq \
    $apkfile \
    /home/hcai/Android/Sdk/platforms/"

($cmd | tee $logout) 3>&1 1>&2 2>&3 | tee $logerr
#${cmd} 2>&1 | tee $logout

stoptime=`date +%s%N | cut -b1-13`
echo "StaticAnalysisTime for $suffix elapsed: " `expr $stoptime - $starttime` milliseconds

exit 0


# hcai vim :set ts=4 tw=4 sws=4

