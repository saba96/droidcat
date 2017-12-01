#!/bin/bash

tmv=${1:-"300"}
port=${2:-"5554"}
avd=${3:-"Nexus-One-10"}
year=${4:-"2010"}
fncat=${5:-"cat-final.txt"}
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

    srcdir=/home/hcai/testbed/instrumentedapks/$cate
    finaldir=$srcdir/installed

    OUTDIR=/home/hcai/testbed/catapkLogs/$cate
    mkdir -p $OUTDIR

	k=1

    flag=false
    for fnapk in $finaldir/*.apk;
	do
        #if [ ${fnapk##*/} = "00E957EB3E3928FF90C77824AD441A2630E9FE8708CD6D179A96FF4362197154.apk" ];then
        #    flag=true
        #fi
        #if [ "$flag" != true ];then
        #    continue
        #fi

        echo "================ RUN INDIVIDUAL APP: ${fnapk##*/} ==========================="
        if [ -s $OUTDIR/${fnapk##*/}.logcat ];
        then
            echo "$fnapk has been processed already, skipped."
            continue
        fi

		echo "tracing $fnapk ..."
		/home/hcai/testbed/setupEmu.sh ${avd} $port
        sleep 3
        pidemu=`ps axf | grep -v grep | grep -a -E "$avd -scale .3 -no-boot-anim -no-window -port $port" | awk '{print $1}'`

		ret=`/home/hcai/bin/apkinstall $fnapk $did`
		n1=`echo $ret | grep -a -c "Success"`
		if [ $n1 -lt 1 ];then 
            echo "killing pid $pidemu, the process of emulator at port $port, from runAndroZooApks_monkey.sh... because app cannot be installed successfully"
            kill -9 $pidemu
            continue
        fi

		# try running it and seeing if it immediately crashes (in one minute)


        adb -s $did logcat -v raw -s "hcai-intent-monitor" "hcai-cg-monitor" &>$OUTDIR/${fnapk##*/}.logcat &
        pidadb=$!
        tgtp=`~/bin/getpackage.sh $fnapk | awk '{print $2}'`
        timeout $tmv "adb -s $did shell monkey -p $tgtp --ignore-crashes --ignore-timeouts --ignore-security-exceptions --throttle 200 10000000 >$OUTDIR/${fnapk##*/}.monkey"
        #killall -9 adb
        #killall -9 emulator

        echo "killing pid $pidemu, the process of emulator at port $port, from runAndroZooApks_monkey.sh..."
        kill -9 $pidemu
        echo "killing pid $pidadb, the process of adb for monitoring emulator at port $port, from runAndroZooApks_monkey.sh..."
        kill -9 $pidadb

		k=`expr $k + 1`
        rm -rf /tmp/android-hcai/*
	done

	echo "totally $k apps in category $cate successfully traced."
}


s=0
cats=""
while read cate;
do
    cats="$cats""$cate""    "
done < $fncat

for cate in $cats;
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
