#!/bin/bash

(test $# -lt 1) && (echo "too few arguments") && exit 0

year=$1
srcdir=/home/hcai/Downloads/AndroZoo/benign-$year
destdir=/home/hcai/testbed/cov.instrumented/AndroZoo/benign-$year
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
    for apk in $srcdir/*.apk;
	do
        pkgname=${apk##*/}
		if [ -s $destdir/$pkgname ];then 
            echo "$apk has been processed already; skipping it"
            continue; 
        fi

		echo "instrument coverage monitoring for app $apk ..."
		timeout 1200 "/home/hcai/testbed/covInstr.sh $apk $destdir/ 1>/dev/null 2>&1"
	done
}

instr

exit 0
