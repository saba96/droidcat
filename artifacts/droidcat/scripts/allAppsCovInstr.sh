#!/bin/bash

#(test $# -lt 1) && (echo "too few arguments") && exit 0

srcdir=/home/hcai/testbed/input/pairs/
destdir=/home/hcai/testbed/cov.instrumented/pairs/
mkdir -p $destdir
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

instr()
{
	for i in $(seq 1 515)
	do
		if [ ! -s $srcdir/${i}.apk ];then continue; fi

		srcp=`~/bin/getpackage.sh $srcdir/${i}.apk | awk '{print $2}'`
		sc=`grep -a -c $srcp $srcdir/installed_apks.txt`
		if [ $i -le 441 -a $sc -lt 1 ];then continue; fi

		echo "instrument coverage monitoring for app ${i}.apk ..."
		timeout 1200 "/home/hcai/testbed/covInstr.sh $srcdir/${i}.apk $destdir/ 1>/dev/null 2>&1"

		echo "chapple" | /home/hcai/testbed/signandalign.sh $destdir/${i}.apk
	done
}

instr

exit 0
