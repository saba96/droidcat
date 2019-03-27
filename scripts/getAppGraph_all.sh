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
    i=0
    for apk in $1/*.apk
    do
        if [ -s $2/${apk##*/}.txt ];then
            echo "$apk already processed, skipping it"
            continue;
        fi

        timeout 1800 "bash getAppGraph.sh $apk >> $2/log.getAppGraph"
        mv $apk.txt $2/

        # for now, compute 2000 samples at most
        ((i=i+1))
        if [ $i -ge 2000 ];then break; fi
    done
}

#getgraph /home/hcai/mama/vs-2016 /home/hcai/mama/graphs/vs-2016
#getgraph /home/hcai/mama/vs-2015 /home/hcai/mama/graphs/vs-2015
#
#getgraph /home/hcai/mama/benign-2014 /home/hcai/mama/graphs/benign-2014
#getgraph /home/hcai/mama/benign-2016 /home/hcai/mama/graphs/benign-2016

#for subdir in 2010  2011  2012  2013  2017 "benign-2010"  "benign-2011" "benign-2012"  "benign-2013"  "benign-2015"
#for subdir in "benign-2015"
for subdir in "malware-2017-more"
do
    getgraph /home/hcai/Downloads/AndroZoo/$subdir /home/hcai/mama/graphs//$subdir
done
