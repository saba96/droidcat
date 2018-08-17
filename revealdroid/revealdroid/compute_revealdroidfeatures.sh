#!/bin/bash
if [ $# -lt 2 ];then
	echo "Usage: $0 apk-dir apk-list"
	exit 1
fi

rootdir=$1
apklist=$2
for fnapk in $rootdir/*.apk;
do
    if [ `grep -a -c ${fnapk##*/} $2` -lt 1 ];then
        echo "skipped $fnapk which was not used by droidspan."
        continue
    fi

    bash excl_prn.sh $fnapk 
done
exit 0
