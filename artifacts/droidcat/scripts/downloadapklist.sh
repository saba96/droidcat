#!/bin/bash
(test $# -lt 1) && exit 0
cat $1 | while read apk;
do
    #/home/hcai/yaogroup/Fang_CollusionAPP/code/AppDownload/download/program/googleplay-api-master/download.py "$apk" ${apk}.apk
    bash downloadapk.sh "$apk" ${apk}.apk
done
