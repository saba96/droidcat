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

getgraph /home/hcai/testbed/input/Contagio/ /home/hcai/Downloads/Mamadroid/mamadroid_code/graphs/malware-obf

getgraph /home/hcai/testbed/input/Drebin/ /home/hcai/Downloads/Mamadroid/mamadroid_code/graphs/malware-drebin

for year in 2014 2015 2016
do
    getgraph /home/hcai/Downloads/AndroZoo/$year /home/hcai/Downloads/Mamadroid/mamadroid_code/graphs/malware-zoo/$year/
done



