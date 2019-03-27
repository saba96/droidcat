#!/bin/bash
if [ $# -lt 1 ];then
	echo "Usage: $0 apk-file"
	exit 1
fi

timeout() {

    time=$1

    # start the command in a subshell to avoid problem with pipes
    # (spawn accepts one command)
    command="/bin/sh -c \"$2\""

    expect -c "set echo \"-noecho\"; set timeout $time; spawn -noecho $command; expect timeout { exit 1 } eof { exit 0 }"    

    if [ $? = 1 ] ; then
        echo "Timeout after ${time} seconds"
    fi

}

apkfile=$1
outdir=$2

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

LOGDIR=out-mudflow-cg
mkdir -p $LOGDIR
logout=$LOGDIR/mudflow-$suffix.out
logerr=$LOGDIR/mudflow-$suffix.err

starttime=`date +%s%N | cut -b1-13`

    #/home/hcai/Android/Sdk/platforms/android-21/android.jar"
cmd="java -Xmx400g -ea -cp ${MAINCP} dynCG.forMudflow \
    $apkfile \
    /home/hcai/Android/Sdk/platforms/ \
    $outdir \
	-catsrc /home/hcai/libs/catsources.txt.final \
	-catsink /home/hcai/libs/catsinks.txt.final"

timeout 1800 "$cmd"
#$cmd
#($cmd | tee $logout) 3>&1 1>&2 2>&3 | tee $logerr
#${cmd} 2>&1 | tee $logout

stoptime=`date +%s%N | cut -b1-13`
echo "StaticAnalysisTime for $suffix elapsed: " `expr $stoptime - $starttime` milliseconds

exit 0


# hcai vim :set ts=4 tw=4 sws=4

