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

getgraph()
{
    mkdir -p $2
    > $2/log.getAppGraph
    for apk in $1/*.apk
    do
        if [ -s $2/${apk##*/}.txt ];then
            echo "$apk already processed, skipping it"
            continue;
        fi

        timeout 1800 "bash getAppGraph.sh $apk >> $2/log.getAppGraph"
        mv $apk.txt $2/
    done
}


#getgraph /home/hcai/testbed/newmalware/ /home/hcai/Downloads/Mamadroid/mamadroid_code/graphs/malware-2017
#getgraph /home/hcai/testbed/newmalware2 /home/hcai/Downloads/Mamadroid/mamadroid_code/graphs/malware-2017

#getgraph /home/hcai/testbed/uniqMalware  /home/hcai/Downloads/Mamadroid/mamadroid_code/graphs/malware-2012

#for subdir in 2013  2014
for subdir in 2014
do
    getgraph /home/hcai/Downloads/VirusShare/$subdir /home/hcai/mama/graphs/vs-$subdir
done

