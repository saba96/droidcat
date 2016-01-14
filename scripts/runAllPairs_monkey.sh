#!/bin/bash

#(test $# -lt 1) && (echo "too few arguments") && exit 0

tmv=${1:-"3600"}
OUTDIR=/home/hcai/testbed/monkeyLogs_explicit
#OUTDIR=/home/hcai/testbed/monkeyLogs_implicit
mkdir -p $OUTDIR

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

#for ((i=1;i<=54;i++))
for ((i=1;i<=7;i++))
do
	echo "================ RUN APP PAIR $i ==========================="
	/home/hcai/testbed/setupEmu.sh Galaxy-Nexus-23
	/home/hcai/testbed/singlePairInstall.sh $i
	adb logcat -v raw -s "hcai-intent-monitor" "hcai-cg-monitor" &>$OUTDIR/${i}.logcat &
	#adb shell monkey --ignore-crashes --ignore-timeouts --ignore-security-exceptions --throttle 200 1
	timeout $tmv "/home/hcai/testbed/runPair.sh $i >$OUTDIR/${i}.monkey"

	adb kill-server
	killall -9 adb
done

exit 0
