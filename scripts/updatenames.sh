#!/bin/bash

srcfn=$1
#APKDIR=/home/hcai/testbed/cg.instrumented/newmalwareall/installed/
APKDIR=/home/hcai/testbed/cg.instrumented/malware/installed/
j=0
#for ((i=1;i<=94;i++))
for ((i=1;i<=415;i++))
do
	if [ ! -s $APKDIR/${i}.apk ];
	then
		continue
	fi
	rt=`cat /home/hcai/testbed/lowcov_malware | awk '{print $1}' | grep -a -c "^${i}.apk.logcat$"`
	if [ $rt -ge 1 ];then
		continue
    fi
    ((j++))
    echo -n "$i.apk."
    head -n $j $srcfn | tail -n1
done
