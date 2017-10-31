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
    > $2/log.getCallSeqs_allbenign
    i=0
    for apk in $1/*.apk
    do
        if [ -s $2/${apk##*/}.txt ];then
            echo "$apk already processed, skipping it"
            continue;
        fi

        timeout 1800 "bash getCallSeqs.sh $apk >> $2/log.getCallSeqs_allbenign"
        mv $apk.txt $2/

        # for now, compute 2000 samples at most
        ((i=i+1))
        if [ $i -ge 2000 ];then break; fi
    done
}

getgraph /home/hcai/mama/benign-2010 /home/hcai/mama/seqs/benign-2010
getgraph /home/hcai/mama/benign-2011 /home/hcai/mama/seqs/benign-2011
getgraph /home/hcai/mama/benign-2012 /home/hcai/mama/seqs/benign-2012
getgraph /home/hcai/mama/benign-2013 /home/hcai/mama/seqs/benign-2013
getgraph /home/hcai/mama/benign-2015 /home/hcai/mama/seqs/benign-2015
