#!/bin/bash

tmv=${1:-"60"}
port=${2:-"5554"}
avd=${3:-"Nexus-One-10"}
year=${4:-"2010"}
did="emulator-$port"

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
tryInstall()
{
    cate=$1

    srcdir=/home/hcai/testbed/cg.instrumented/AndroZoo/$cate
    finaldir=$srcdir

    OUTDIR=/home/hcai/testbed/otheremulators/androZooLogs-$avd/$cate
    mkdir -p $OUTDIR

	k=1

    triedlist=otheremulators/triedlist.$avd.benign$year.txt
    > $triedlist

    flag=false
    for fnapk in $finaldir/*.apk;
	do

        if [ `grep -a -c ${fnapk##*/} otheremulators/apkname_run_fail_$year.txt` -lt 1 ];then
            echo "$fnapk was not included in previous run-time study"
            continue
        fi

        echo "================ RUN INDIVIDUAL APP: ${fnapk##*/} ==========================="
        if [ -s $OUTDIR/${fnapk##*/}.logcat ];
        then
            echo "$fnapk has been processed already, skipped."
            continue
        fi

        if [ `grep -a -c ${fnapk##*/} $triedlist` -lt 1 ];then
            echo "$fnapk has been tried before, skipped."
            continue
        fi

        echo "$fnapk" >> $triedlist

        echo "tracing $fnapk ..."
        #timeout 150 "/home/hcai/testbed/setupEmu.sh ${avd} $port"
        /home/hcai/testbed/setupEmu.sh ${avd} $port
        if [ $? -ne 0 ];then
            echo "emulator booting got stuck; bailed out"
            killall -9 qemu-system-x86_64 
            killall -9 qemu-system-i386
            killall -9 adb
            continue
        fi
        #/home/hcai/testbed/setupEmu.sh ${avd} $port
        sleep 1
        pidemu=`ps axf | grep -v grep | grep "$avd -scale .3 -no-window -port $port" | awk '{print $1}'`

        echo "now installing $fnapk..."
		#ret=`timeout 30 "/home/hcai/bin/apkinstall $fnapk $did"`
		ret=`/home/hcai/bin/apkinstall $fnapk $did`
		n1=`echo $ret | grep -a -c "Success"`
		if [ $n1 -lt 1 ];then 
            echo "killing pid $pidemu, the process of emulator at port $port, from runAndroZooApks_monkey.sh... because app cannot be installed successfully"
            echo $ret
            kill -9 $pidemu
            continue
        fi

		# try running it and seeing if it immediately crashes (in one minute)

        adb -s $did logcat -v raw -s "hcai-intent-monitor" "hcai-cg-monitor" &>$OUTDIR/${fnapk##*/}.logcat &
        pidadb=$!
        tgtp=`~/bin/getpackage.sh $fnapk | awk '{print $2}'`
        timeout $tmv "adb -s $did shell monkey -p $tgtp --ignore-crashes --ignore-timeouts --ignore-security-exceptions --throttle 200 10000000 >$OUTDIR/${fnapk##*/}.monkey"

        #timeout 30 "/home/hcai/bin/apkuninstall $fnapk $did"
        /home/hcai/bin/apkuninstall $fnapk $did
        kill -9 $pidadb

		k=`expr $k + 1`

        echo "killing pid $pidemu, the process of emulator at port $port, from runAndroZooApks_monkey.sh..."
        kill -9 $pidemu
        rm -rf /tmp/android-hcai/*
	done


	echo "totally $k apps in category $cate successfully traced."
}


s=0

#for cate in 2016 2015 2014
#for cate in 2013 2011 2010
#for cate in "benign-$year"
for cate in "$year"
do
    c=0
    echo "================================="
    echo "try installing category $cate ..."
    echo "================================="
    echo
    echo

    tryInstall $cate
    rm -rf /tmp/android-hcai/*
done

exit 0
