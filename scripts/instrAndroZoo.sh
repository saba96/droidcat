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
>log.instr.androzoo.2nd
#for year in 2016 2015 2014
for year in 2013 2011 2010
do
    c=0
    echo "================================="
    echo "instrument year $year ..."
    echo "================================="
    echo
    echo

    tgtdir=/home/hcai/testbed/cg.instrumented/AndroZoo/$year
    mkdir -p $tgtdir
    ls /home/hcai/Downloads/AndroZoo/$year/*.apk | while read apk;
    do
        timeout 600 "cgInstr.sh $apk $tgtdir >>log.instr.androzoo.2nd"
        echo "$apk instrumented."
        ((c+=1))
    done
    echo "$c apps in year $year instrumented successfully."

    echo
    echo
    ((s+=c))
done
echo "$s apps in total instrumented successfully."

exit $s
