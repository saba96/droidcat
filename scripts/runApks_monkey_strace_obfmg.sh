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

    #srcdir=/home/hcai/testbed/$cate
    #srcdir=/home/hcai/Downloads/AndroZoo/$cate/BENIGN
    srcdir=/home/hcai/testbed/input/
    finaldir="$srcdir/$cate"

    OUTDIR=/home/hcai/testbed/straceLogs/$cate
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
        if [ ! -s /home/hcai/testbed/PraguardMalgenomeLogs/${fnapk##*/}.logcat ];then
            continue
        fi

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
        sleep 2
        pidemu=`ps axf | grep -v "grep" | grep "$avd -scale .3 -no-boot-anim -no-window -port $port" | awk '{print $1}'`

		ret=`/home/hcai/bin/apkinstall $fnapk $did`
		n1=`echo $ret | grep -a -c "Success"`
		if [ $n1 -lt 1 ];then 
            kill -9 $pidemu
            # no need to retry if installation fails
            echo "installation failed for $fnapk: $ret" 1> $OUTDIR/${fnapk##*/}.logcat 2>&1
            continue
        fi

		# try running it and seeing if it immediately crashes (in one minute)
        trials=3
        for ((t=1;t<=$trials;t++));
        do
            echo "**** trial no. $t ... ***"

            tgtp=`~/bin/getpackage.sh $fnapk | awk '{print $2}'`
            adb -s $did shell monkey -p $tgtp --ignore-crashes --ignore-timeouts --ignore-security-exceptions --throttle 200 10000000 2>&1 1>$OUTDIR/${fnapk##*/}.monkey &
            pidmonkey=$!

            sleep 1
            pidapp=`adb -s $did shell ps | grep -v "grep" | grep "$tgtp" | awk '{print $2}'`
            if [ ${#pidapp} -lt 1 ];then
                echo "app $tgtp did not start; will try again"
                #kill -9 $pidemu
                kill -9 $pidmonkey
                continue
            else
                echo "app $tgtp started with pid=$pidapp"
            fi

            #timeout $tmv "adb -s $did shell strace -p $pidapp $ >$OUTDIR/${fnapk##*/}.logcat"
            #adb -s $did shell strace -p $pidapp -cfF >$OUTDIR/${fnapk##*/}.logcat &
            adb -s $did shell strace -p $pidapp -c >$OUTDIR/${fnapk##*/}.logcat &
            pidadb=$!

            sleep $tmv
            /home/hcai/bin/apkuninstall $fnapk $did

            kill -9 $pidmonkey
            kill -9 $pidadb
            k=`expr $k + 1`
            break
        done

        kill -9 $pidemu
        rm -rf /tmp/android-hcai/*
	done

	echo "totally $k apps in category $cate successfully traced."
}


s=0

#for cate in 2016 2015 2014
#for cate in 2013 2011 2010
#for cate in "benign-2016"
#for cate in "newmalwareall/all"
#for cate in "benign-2014"
#for cate in 2013 2012



for cate in "PraguardMalgenome"
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
