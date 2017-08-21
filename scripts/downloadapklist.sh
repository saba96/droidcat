#!/bin/bash
(test $# -lt 1) && exit 0
cat $1 | while read apk;
do
    bash downloadapk.sh "$apk" ${apk}.apk
done
