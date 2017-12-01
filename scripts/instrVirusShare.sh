#!/usr/bin bash 

[ $# -lt 0 ] &&  echo "too few arguments." && exit 1

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


s=0
#for year in 2016 2015 2014
for year in 2013
do
    local c=0
    echo "================================="
    echo "instrument year $year ..."
    echo "================================="
    echo
    echo
    >log.instr.virusshare.$year

    tgtdir=/home/hcai/testbed/cg.instrumented/VirusShare/$year
    mkdir -p $tgtdir
    for apk in /home/hcai/mama/vs-$year/*.apk
    do
        if [ -s $tgtdir/${apk##*/} ];then
            echo "$apk already instrumented, skipped"
            continue
        fi
        timeout 3600 "cgInstr.sh $apk $tgtdir 2>/dev/null >>log.instr.virusshare.$year"
        echo "$apk instrumented."
        ((c+=1))
        if [ $c -ge 2500 ];then break; fi
    done
    echo "$c apps in year $year instrumented successfully."

    echo
    echo
    ((s+=c))
done
echo "$s apps in total instrumented successfully."

exit $s
