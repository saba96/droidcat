#!/usr/bin bash 

[ $# -lt 1 ] &&  echo "too few arguments." && exit 1

cats=$1

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
cat $cats | while read category;
do
    c=0
    echo "================================="
    echo "instrument category $category ..."
    echo "================================="
    echo
    echo

    tgtdir=instrumentedapks/$category
    mkdir -p $tgtdir
    ls /home/hcai/bin/apks2017/$category/*.apk | while read apk;
    do
        timeout 600 "cgInstr.sh $apk $tgtdir"
        echo "$apk instrumented."
        ((c+=1))
    done
    echo "$c apps in category $category instrumented successfully."

    echo
    echo
    ((s+=c))
done
echo "$s apps in total instrumented successfully."

exit $s
    
