#!/bin/bash

for item in "$@";
do
    if [ ! -d $item ];then continue; fi
    echo "$item `ls $item/*.logcat | wc -l`"
done
exit 0
