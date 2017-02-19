#!/bin/bash

#(test $# -lt 1) && (echo "too few arguments") && exit 0

tmv=${1:-"3600"}
destdir=/home/hcai/testbed/cg.instrumented/pairs/

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

runPairs() {
	cat=$1
	for ((i=1;i<=100;i++))
	do
		finaldir=$destdir/${cat}_installed
		OUTDIR=/home/hcai/testbed/appPairLogsNew_${cat}
		mkdir -p $OUTDIR

		if [ ! -s $finaldir/$i/s.apk ];then continue; fi
		if [ ! -s $finaldir/$i/t.apk ];then continue; fi
		if [ -s $OUTDIR/${i}.logcat ];then 
			echo "app pair $i has been processed, skipped it now."
			continue
		fi

		echo "================ RUN APP PAIR $i ==========================="
		/home/hcai/testbed/setupEmu.sh Galaxy-Nexus-23
		~/bin/apkinstall $finaldir/$i/s.apk
		~/bin/apkinstall $finaldir/$i/t.apk

		adb logcat -v raw -s "hcai-intent-monitor" "hcai-cg-monitor" &>$OUTDIR/${i}.logcat 2>&1 &
		#adb shell monkey --ignore-crashes --ignore-timeouts --ignore-security-exceptions --throttle 200 1
		timeout $tmv "/home/hcai/testbed/runPairNew.sh $i $cat >$OUTDIR/${i}.monkey"

		adb kill-server
		killall -9 adb
	done
}

runPairs "implicit"
runPairs "explicit"

exit 0

