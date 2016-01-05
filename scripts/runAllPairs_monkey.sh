#!/bin/bash

#(test $# -lt 1) && (echo "too few arguments") && exit 0

tmv=${1:-"600"}

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

for ((i=1;i<=16;i++))
do
	echo "================ RUN APP PAIR $i ==========================="
	/home/hcai/testbed/setupEmu.sh Galaxy-Nexus-23
	/home/hcai/testbed/singlePairInstall.sh $i
	adb logcat -v raw -s "hcai-intent-monitor" "hcai-cg-monitor" &>/home/hcai/testbed/monkeyLogs/${i}.logcat &
	#adb shell monkey --ignore-crashes --ignore-timeouts --ignore-security-exceptions --throttle 200 1
	timeout $tmv "/home/hcai/testbed/runPair.sh $i >/home/hcai/testbed/monkeyLogs/${i}.monkey"

	killall adb
done

exit 0
