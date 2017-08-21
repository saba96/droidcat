#!/bin/bash

spyear=$1

while read line;
do
    _year=`echo $line | awk -F, '{print $4}'`
    year=${_year%%-*}
    if [ $year -ne $spyear ];then
        continue
    fi

    echo "downloading next malware from Year $year ..."
    mkdir -p $year
    sha256=`echo $line | awk -F, '{print $1}'`
    wget "https://androzoo.uni.lu/api/download?apikey=b66685ec9294443de568e5727b176f00288c911fde2b0534bd5c4f965a742ca5&sha256=${sha256}" -O $year/${sha256}.apk

done < malware.csv.sorted

exit 0
