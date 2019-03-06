#!/bin/bash

tmv=$1
fnapk=$2
did=$3
OUTDIR=$4

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

#ret=`timeout 120 "/home/hcai/bin/apkinstall $fnapk $did"`
echo "now installing $fnapk"
ret=`/home/hcai/bin/apkinstall $fnapk $did`
n1=`echo $ret | grep -a -c "Success"`
if [ $n1 -lt 1 ];then 
    echo $ret
    exit 1
fi

echo "now tracing $fnapk"
# try running it and seeing if it immediately crashes (in one minute)
adb -s $did logcat -v raw -s "hcai-intent-monitor" "hcai-cg-monitor" &>$OUTDIR/${fnapk##*/}.logcat &
pidadb=$!
tgtp=`~/bin/getpackage.sh $fnapk | awk '{print $2}'`
timeout $tmv "adb -s $did shell monkey -p $tgtp --ignore-crashes --ignore-timeouts --ignore-security-exceptions --throttle 200 10000000 >$OUTDIR/${fnapk##*/}.monkey"

#timeout 30 "/home/hcai/bin/apkuninstall $fnapk $did"
/home/hcai/bin/apkuninstall $fnapk $did
kill -9 $pidadb
exit 0
