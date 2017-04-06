#/bin/bash

srcdir=/home/hcai/testbed/cg.instrumented/pairs/
finaldir=$srcdir/installed
mkdir -p $finaldir

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

installOne()
{
	fnapk=$1
	/home/hcai/testbed/setupEmu.sh Galaxy-Nexus-23
	ret=`~/bin/apkinstall $fnapk`
	n1=`echo $ret | grep -a -c "Success"`
	if [ $n1 -lt 1 ];then return 1; fi

	# try running it and seeing if it immediately crashes (in one minute)

	adb logcat -v raw &>/tmp/tmp.log &
	tgtp=`~/bin/getpackage.sh $fnapk | awk '{print $2}'`
	timeout 60 "adb shell monkey -p $tgtp --ignore-crashes --ignore-timeouts --ignore-security-exceptions --throttle 200 10000000 >/tmp/tmp.monkey"
	killall -9 adb

	killall -9 emulator
	#apkuninstall $fnapk

	n2=`cat /tmp/tmp.log | grep -a -c -E "FATAL EXCEPTION|java.lang.VerifyError: Rejecting"`
	rm /tmp/tmp.log
	if [ $n2 -ge 1 ];then return 2; fi

	return 0
}

tryInstall()
{
	k=1
	mkdir -p $finaldir
	for i in $(seq 1 550)
	do
		if [ ! -s $srcdir/${i}.apk ];then continue; fi
		if [ -s $finaldir/${i}.apk ];then 
			echo "app $i has been processed, skipped it now."
			continue
		fi

		echo "processing app $i ..."
		installOne "$srcdir/${i}.apk"
		if [ $? -ne 0 ];then continue; fi

		cp $srcdir/${i}.apk $finaldir/

		echo "successfully installed instrumented benign app $i"

		k=`expr $k + 1`
	done
	echo "totally $k apps successfully installed and able to run okay."
}

tryInstall 

exit 0

