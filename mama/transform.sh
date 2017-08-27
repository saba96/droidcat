#!/bin/bash 

for apktxt in $1/*.apk.txt
do
    echo "processed $apktxt"
    bash transformone.sh $apktxt > tmp
    mv tmp $apktxt

    echo "processed $apktxt"
done
exit 0
