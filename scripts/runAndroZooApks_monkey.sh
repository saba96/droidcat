#!/bin/bash

#tmv=${1:-"600"}
tmv=${1:-"300"}
port=${2:-"5554"}
avd=${3:-"Nexus-One-10"}
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

    OUTDIR=/home/hcai/testbed/androZooLogs/$cate
    mkdir -p $OUTDIR

	k=1

    flag=false
    for fnapk in $finaldir/*.apk;
	do
        #if [ ${fnapk##*/} = "00634FE7BDEAEA00D66FEF5EB53A3DC001A8E7B3F9046771D61DC240B4A4E693.apk" ];then
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
		#/home/hcai/testbed/setupEmu.sh Galaxy-Nexus-23
		#/home/hcai/testbed/setupEmu.sh Nexus-One-10
		/home/hcai/testbed/setupEmuMulti.sh $avd $port
        sleep 3
        pidemu=`ps axf | grep -v "grep" | grep "$avd -scale .3 -no-boot-anim -no-window -port $port" | awk '{print $1}'`

		ret=`/home/hcai/bin/apkinstall $fnapk $did`
		n1=`echo $ret | grep -a -c "Success"`
		if [ $n1 -lt 1 ];then 
            #killall -9 emulator
            #killall -9 adb
            kill -9 $pidemu
            continue
        fi

		# try running it and seeing if it immediately crashes (in one minute)


        adb -s $did logcat -v raw -s "hcai-intent-monitor" "hcai-cg-monitor" &>$OUTDIR/${fnapk##*/}.logcat &
        pidlogcat=$!
        tgtp=`~/bin/getpackage.sh $fnapk | awk '{print $2}'`
        timeout $tmv "adb -s $did shell monkey -p $tgtp --ignore-crashes --ignore-timeouts --ignore-security-exceptions --throttle 200 10000000 >$OUTDIR/${fnapk##*/}.monkey"
        #killall -9 adb
        #killall -9 emulator
        kill -9 $pidlogcat
        kill -9 $pidemu
		k=`expr $k + 1`
        rm -rf /tmp/android-hcai/*
	done

	echo "totally $k apps in category $cate successfully traced."
}


s=0

#for cate in 2016 2015 2014
#for cate in 2013 2011 2010
#for cate in "benign-2016"
for cate in 2012
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
