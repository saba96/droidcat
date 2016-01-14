#!/bin/bash

#(test $# -lt 1) && (echo "too few arguments") && exit 0

tmv=${1:-"3600"}
#OUTDIR=/home/hcai/testbed/singleAppLogs_explicit
OUTDIR=/home/hcai/testbed/singleAppLogs_implicit
mkdir -p $OUTDIR

destdir=/home/hcai/testbed/cg.instrumented/pairs/
finaldir=$destdir/implicit_installed
#finaldir=$destdir/explicit_installed

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

for ((i=21;i<=54;i++))
#for ((i=1;i<=7;i++))
do
	/home/hcai/testbed/setupEmu.sh Galaxy-Nexus-23
	apkinstall $finaldir/$i/t.apk
	adb logcat -v raw -s "hcai-intent-monitor" "hcai-cg-monitor" &>$OUTDIR/${i}-t.logcat &
	tgtp=`~/bin/getpackage.sh $finaldir/$i/t.apk | awk '{print $2}'`
	timeout $tmv "adb shell monkey -p $tgtp --ignore-crashes --ignore-timeouts --ignore-security-exceptions --throttle 200 10000000 >$OUTDIR/${i}-t.monkey"
	killall adb

	echo "================ RUN INDIVIDUAL APPS IN PAIR $i ==========================="
	/home/hcai/testbed/setupEmu.sh Galaxy-Nexus-23
	apkinstall $finaldir/$i/s.apk
	adb logcat -v raw -s "hcai-intent-monitor" "hcai-cg-monitor" &>$OUTDIR/${i}-s.logcat &
	srcp=`~/bin/getpackage.sh $finaldir/$i/s.apk | awk '{print $2}'`
	timeout $tmv "adb shell monkey -p $srcp --ignore-crashes --ignore-timeouts --ignore-security-exceptions --throttle 200 10000000 >$OUTDIR/${i}-s.monkey"
	killall adb

done

exit 0
