#!/bin/bash

(test $# -lt 1) && (echo "too few arguments") && exit 0

rep=${1:-"benign-new-firstrep"}
cat=${2:-"implicit"}
APKDIR=/home/hcai/testbed/input/pairs.secondset/$cat/
TRACEDIR=/home/hcai/testbed/$rep/singleAppLogsNew_$cat

for ((i=1;i<=250;i++))
do
	if [ ! -s $APKDIR/$i/s.apk ];then continue; fi
	if [ ! -s $APKDIR/$i/t.apk ];then continue; fi

	srt=`cat lowcov_benign_set2.${cat}.final | awk '{print $1}' | grep -a -c -E "^${i}-s.logcat$"`
	if [ $srt -lt 1 ];then
		echo "result for $cat $i/s.apk" 
	fi

	trt=`cat lowcov_benign_set2.${cat}.final | awk '{print $1}' | grep -a -c "^${i}-t.logcat$"`
	if [ $trt -lt 1 ];then
		echo "result for $cat $i/t.apk" 
	fi
done

exit 0
