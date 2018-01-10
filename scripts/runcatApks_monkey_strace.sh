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

    srcdir=/home/hcai/bin/apks2017/$cate
    finaldir=$srcdir

    OUTDIR=/home/hcai/testbed/straceLogs/benign2017/$cate
    mkdir -p $OUTDIR

	k=1

    #/home/hcai/testbed/setupEmu.sh Galaxy-Nexus-23
    #/home/hcai/testbed/setupEmu.sh Nexus-One-10
    /home/hcai/testbed/setupEmu.sh $avd $port
    sleep 3
    pidemu=`ps axf | grep -v "grep" | grep "$avd -scale .3 -no-boot-anim -no-window -port $port" | awk '{print $1}'`

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

		ret=`/home/hcai/bin/apkinstall $fnapk $did`
		n1=`echo $ret | grep -a -c "Success"`
		if [ $n1 -lt 1 ];then 
            #kill -9 $pidemu
            continue
        fi

		# try running it and seeing if it immediately crashes (in one minute)

        tgtp=`~/bin/getpackage.sh $fnapk | awk '{print $2}'`
        adb -s $did shell monkey -p $tgtp --ignore-crashes --ignore-timeouts --ignore-security-exceptions --throttle 200 10000000 &>$OUTDIR/${fnapk##*/}.monkey &
        pidmonkey=$!

        sleep 3
        pidapp=`adb -s $did shell ps | grep -v "grep" | grep "$tgtp" | awk '{print $2}'`
        if [ ${#pidapp} -lt 1 ];then
            echo "app $tgtp did not start"
            kill -9 $pidmonkey
            continue
        else
            echo "app $tgtp started with pid=$pidapp"
        fi
        #timeout $tmv "adb -s $did shell strace -p $pidapp $ >$OUTDIR/${fnapk##*/}.logcat"
        adb -s $did shell strace -p $pidapp -cfF >$OUTDIR/${fnapk##*/}.logcat &
        pidadb=$!

        sleep $tmv
        /home/hcai/bin/apkuninstall $fnapk $did

        kill -9 $pidmonkey
        kill -9 $pidadb
        #kill -9 $pidemu
		k=`expr $k + 1`
        rm -rf /tmp/android-hcai/*
	done

	echo "totally $k apps in category $cate successfully traced."
    kill -9 $pidemu
}


cats=""
while read cate;
do
    cats="$cats""$cate""    "
done < cat-final.txt

for cate in $cats;
do
    echo "================================="
    echo "try installing category $cate ..."
    echo "================================="
    echo
    echo

    tryInstall $cate
    rm -rf /tmp/android-hcai/*
done

exit 0
