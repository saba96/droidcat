#!/bin/bash

for i in $@
do
    md5=`md5sum $i | awk '{print $1}'`
    mv $i $md5.apk
done

exit 0
