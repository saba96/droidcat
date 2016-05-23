#!/bin/bash

(test $# -lt 1) && (echo "too few arguments") && exit 0

rep=${1:-"first_rep"}
cat=${2:-"implicit"}
APKDIR=/home/hcai/testbed/input/pairs/$cat/
TRACEDIR=/home/hcai/testbed/$rep/singleAppLogs_$cat

pairs=7
if [ $cat = "implicit" ];then
	pairs=54
fi

resultdir=/home/hcai/testbed/results/ICCReport/$rep
mkdir -p $resultdir $resultdir/$cat
resultlog=$resultdir/log.ICCReport.all.$cat
> $resultlog
for ((i=1;i<=${pairs};i++))
do
	echo "result for $cat $i/s.apk" >> $resultlog 2>&1
	/home/hcai/bin/getpackage.sh /home/hcai/testbed/input/pairs/$cat/$i/s.apk >> $resultlog 2>&1
	sh /home/hcai/testbed/ICCReport.sh \
		/home/hcai/testbed/input/pairs/$cat/$i/s.apk \
		/home/hcai/testbed/$rep/singleAppLogs_$cat/$i-s.logcat >> $resultlog 2>&1

	echo "result for $cat $i/t.apk" >> $resultlog 2>&1
	/home/hcai/bin/getpackage.sh /home/hcai/testbed/input/pairs/$cat/$i/t.apk >> $resultlog 2>&1
	sh /home/hcai/testbed/ICCReport.sh \
		/home/hcai/testbed/input/pairs/$cat/$i/t.apk \
		/home/hcai/testbed/$rep/singleAppLogs_$cat/$i-t.logcat >> $resultlog 2>&1
done
#mv /home/hcai/testbed/{gicc.txt,dataicc.txt,extraicc.txt,icclink.txt,icccov.txt,bothdataicc.txt} \
#	/home/hcai/testbed/results/ICCReport/$rep/$cat/

exit 0
