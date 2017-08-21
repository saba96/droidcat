#!/bin/bash

for apk in $@;
do
    pkg=`~/bin/getpackage.sh $apk | awk '{print $2}'`
    echo -e "${pkg}\t${apk}"
done
