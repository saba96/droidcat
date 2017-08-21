#!/bin/bash

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
    mkdir -p $finaldir

	k=1

    for fnapk in $srcdir/*.apk;
	do
		if [ -s $srcdir/installed/${fnapk##*/} ];then 
			echo "$fnapk has been processed, skipped it now."
			continue
		fi
		echo "processing $fnapk ..."
		#/home/hcai/testbed/setupEmu.sh Galaxy-Nexus-23
		/home/hcai/testbed/setupEmu.sh Nexus-One-10
        sleep 3

		ret=`/home/hcai/bin/apkinstall $fnapk`
		n1=`echo $ret | grep -a -c "Success"`
		if [ $n1 -lt 1 ];then 
            killall -9 emulator
            killall -9 adb
            continue
        fi

		# try running it and seeing if it immediately crashes (in one minute)

		adb logcat -v raw -s "hcai-intent-monitor" "hcai-cg-monitor" &>/tmp/tmp.log &
		tgtp=`/home/hcai/bin/getpackage.sh $fnapk | awk '{print $2}'`
		timeout 60 "adb shell monkey -p $tgtp --ignore-crashes --ignore-timeouts --ignore-security-exceptions --throttle 200 10000000 >/tmp/tmp.monkey"

		killall -9 emulator
		killall -9 adb

		#apkuninstall $fnapk

		n2=`cat /tmp/tmp.log | grep -a -c -E "FATAL EXCEPTION|java.lang.VerifyError: Rejecting"`
		if [ $n2 -ge 1 ];then continue; fi

		cp -r $fnapk $finaldir/

		echo "successfully installed instrumented app: $fnapk"

		k=`expr $k + 1`
	done
	echo "totally $k apps in category $cate successfully installed and able to run okay"
}


s=0
cats=""
while read cate;
do
    cats="$cats""$cate""    "
done < $1

for cate in $cats;
do
    c=0
    echo "================================="
    echo "try installing category $cate ..."
    echo "================================="
    echo
    echo

    tryInstall $cate
done

exit 0
