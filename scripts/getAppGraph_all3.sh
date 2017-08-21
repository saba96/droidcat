#!/bin/bash 

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

        bash getAppGraph.sh $apk >> $2/log.getAppGraph
        mv $apk.txt $2/
    done
}


getgraph /home/hcai/testbed/newmalware/ /home/hcai/Downloads/Mamadroid/mamadroid_code/graphs/malware-2017
getgraph /home/hcai/testbed/newmalware2 /home/hcai/Downloads/Mamadroid/mamadroid_code/graphs/malware-2017

getgraph /home/hcai/testbed/uniqMalware  /home/hcai/Downloads/Mamadroid/mamadroid_code/graphs/malware-2012

