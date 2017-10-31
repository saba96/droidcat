#!/bin/bash

#(test $# -lt 1) && (echo "too few arguments") && exit 0

#tmv=${1:-"3600"}
tmv=${1:-"300"}
did=${2:-"emulator-5554"}
OUTDIR=/home/hcai/testbed/PraguarMalgenomeLogs
mkdir -p $OUTDIR

destdir=/home/hcai/testbed/cg.instrumented/PraguardMalgenome/
#finaldir=$destdir/installed
finaldir=$destdir/

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

#ls $finaldir/*.apk | while read fnapk;
for fnapk in $finaldir/*.apk;
do
	echo "================ RUN INDIVIDUAL APP: ${fnapk##*/} ==========================="
	if [ -s $OUTDIR/${fnapk##*/}.logcat ];
	then
		echo "$fnapk has been processed already, skipped."
		continue
	fi

	#srt=`cat lowcov_malware_apks | awk '{print $1}' | grep -a -c "^${fnapk##*/}$"`
	#if [ $srt -ge 1 ];then
	#	continue
	#fi

	#/home/hcai/testbed/setupEmu.sh Galaxy-Nexus-23 $did
    /home/hcai/testbed/setupEmu.sh Nexus-One-10 $did
	apkinstall $fnapk $did
	adb -s $did logcat -v raw -s "hcai-intent-monitor" "hcai-cg-monitor" &>$OUTDIR/${fnapk##*/}.logcat &
	tgtp=`~/bin/getpackage.sh $fnapk | awk '{print $2}'`
	timeout $tmv "adb -s $did shell monkey -p $tgtp --ignore-crashes --ignore-timeouts --ignore-security-exceptions --throttle 200 10000000 >$OUTDIR/${fnapk##*/}.monkey"
	killall -9 adb
	killall -9 emulator
done

exit 0
