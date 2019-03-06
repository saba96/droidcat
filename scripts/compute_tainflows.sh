#!/bin/bash
if [ $# -lt 2 ];then
	echo "Usage: $0 apk-dir apk-list"
	exit 1
fi

rootdir=$1
apklist=$2
resdir=$3

mkdir -p $resdir

>> $resdir/timecost.txt

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

for fnapk in $rootdir/*.apk;
do
    if [ `grep -a -c ${fnapk##*/} $2` -lt 1 ];then
        echo "skipped $fnapk which was not used by droidspan."
        continue
    fi
    
    if [ -f $resdir/${fnapk##*/}.txt ];then
        echo "$fnapk has been processed, skipped."
        continue
    fi

    timeout 1800 "bash getMudflowpaths.sh $fnapk $resdir | grep "elapsed" >> $resdir/timecost.txt"
done
exit 0
