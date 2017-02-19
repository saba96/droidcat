#!/bin/bash

(test $# -lt 1) && (echo "too few arguments") && exit 0

rep=${1:-"first_rep"}
cat=${2:-"implicit"}
APKDIR=/home/hcai/testbed/input/pairs/$cat/
TRACEDIR=/home/hcai/testbed/$rep/monkeyLogs_$cat

pairs=7
if [ $cat = "implicit" ];then
	pairs=54
fi

resultdir=/home/hcai/testbed/results/interAppICCReport/$rep
mkdir -p $resultdir $resultdir/$cat
resultlog=$resultdir/log.interAppICCReport.all.$cat
> $resultlog
for ((i=1;i<=${pairs};i++))
do
	echo "result for $cat pair $i" >> $resultlog 2>&1
	/home/hcai/bin/getpackage.sh /home/hcai/testbed/input/pairs/$cat/$i/s.apk >> $resultlog 2>&1
	/home/hcai/bin/getpackage.sh /home/hcai/testbed/input/pairs/$cat/$i/t.apk >> $resultlog 2>&1
	sh /home/hcai/testbed/interAppICCReport.sh \
		/home/hcai/testbed/input/pairs/$cat/$i \
		/home/hcai/testbed/$rep/monkeyLogs_$cat/$i.logcat >> $resultlog 2>&1
done
mv /home/hcai/testbed/{gicc.txt,dataicc.txt,extraicc.txt,icclink.txt,bothdataicc.txt,pairicc.txt} \
	/home/hcai/testbed/results/interAppICCReport/$rep/$cat/

exit 0
