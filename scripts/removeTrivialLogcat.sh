#!/bin/bash

(test $# -lt 1) && (echo "too few arguments") && exit 0

threshold=${2:-"10240"}

cnt=0
for fn in $1/*.logcat
do
    sz=`ls -l $fn | awk '{print $5}'`
    if [ $sz -lt $threshold ];then 
        fnmonkey=${fn%.*}.monkey
        echo "to remove $fn because of its trivial size of $sz, and accordingly $fnmonkey"
        rm -f $fn $fnmonkey
        ((cnt++))
    fi
done
echo "totally ${cnt}*2 ($((cnt*2))) files removed due to their size less than $threshold"
exit 0

