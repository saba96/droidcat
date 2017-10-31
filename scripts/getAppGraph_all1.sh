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

#getgraph /home/hcai/testbed/input/pairs.thirdset /home/hcai/Downloads/Mamadroid/mamadroid_code/graphs/benign-2015


cats=""
while read cate;
do
    cats="$cats""$cate""    "
done < /home/hcai/testbed/cat-partial.txt

for cate in $cats;
do
    getgraph /home/hcai/bin/apks2017/$cate /home/hcai/Downloads/Mamadroid/mamadroid_code/graphs/benign-2017
done


