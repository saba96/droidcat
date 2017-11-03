#!/bin/bash

tmv=${1:-"300"}
did=${2:-"emulator-5554"}

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

profile()
{
    cate=$1

    srcdir=/home/hcai/testbed/cg.instrumented/VirusShare/$cate
    finaldir=$srcdir

    OUTDIR=/home/hcai/testbed/virusShareLogs/$cate
    mkdir -p $OUTDIR

	k=1

    for fnapk in $finaldir/*.apk;
	do
        echo "================ RUN INDIVIDUAL APP: ${fnapk##*/} ==========================="
        if [ -s $OUTDIR/${fnapk##*/}.logcat ];
        then
            echo "$fnapk has been processed already, skipped."
            continue
        fi

		echo "tracing $fnapk ..."
		#/home/hcai/testbed/setupEmu.sh Galaxy-Nexus-23
		/home/hcai/testbed/setupEmu.sh Nexus-One-10
        sleep 3

		ret=`/home/hcai/bin/apkinstall $fnapk $did`
		n1=`echo $ret | grep -a -c "Success"`
		if [ $n1 -lt 1 ];then 
            killall -9 emulator
            killall -9 adb
            continue
        fi

        adb -s $did logcat -v raw -s "hcai-intent-monitor" "hcai-cg-monitor" &>$OUTDIR/${fnapk##*/}.logcat &
        tgtp=`~/bin/getpackage.sh $fnapk | awk '{print $2}'`
        timeout $tmv "adb -s $did shell monkey -p $tgtp --ignore-crashes --ignore-timeouts --ignore-security-exceptions --throttle 200 10000000 >$OUTDIR/${fnapk##*/}.monkey"
        killall -9 adb
        killall -9 emulator
		k=`expr $k + 1`

        rm -rf /tmp/android-hcai/*
	done

	echo "totally $k apps in category $cate successfully traced."
}

#bash instrVirusShare.sh

s=0

#for cate in 2016 2015 2014
for cate in 2016
do
    c=0
    echo "================================="
    echo "profiling apps from year $cate ..."
    echo "================================="
    echo
    echo

    profile $cate
    rm -rf /tmp/android-hcai/*
done

exit 0

