#!/bin/bash

#(test $# -lt 1) && (echo "too few arguments") && exit 0

srcdir=/home/hcai/testbed/input/pairs/
destdir=/home/hcai/testbed/cg.instrumented/pairs/
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
	>log.instr-benign-set3
	for i in $(seq 362 515)
	do
		if [ ! -s $srcdir/${i}.apk ];then continue; fi

		echo "instrumenting $srcdir/${i}.apk ......"
		timeout 1200 "/home/hcai/testbed/cgInstr.sh $srcdir/${i}.apk $destdir/ 2>>log.instr-benign-set3 1>/dev/null"

		echo "chapple" | /home/hcai/testbed/signandalign.sh $destdir/${i}.apk
	done
}

instr

exit 0
