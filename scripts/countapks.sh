#!/bin/bash

for item in "$@";
do
    if [ ! -d $item ];then continue; fi
    echo "$item `ls $item/*.apk | wc -l`"
done
exit 0
