#!/bin/bash

(test $# -lt 1) && (echo "too few arguments") && exit 0

rep=${1:-"second_rep"}
cat=${2:-"implicit"}
APKDIR=/home/hcai/testbed/input/pairs/$cat/
TRACEDIR=/home/hcai/testbed/$rep/singleAppLogs_$cat

resultdir=/home/hcai/testbed/results/generalReport/$rep
mkdir -p $resultdir $resultdir/$cat
resultlog=$resultdir/log.generalReport.all.$cat
> $resultlog
for ((i=1;i<=54;i++))
do
	echo "result for $cat $i/s.apk" >> $resultlog 2>&1
	/home/hcai/bin/getpackage.sh /home/hcai/testbed/input/pairs/$cat/$i/s.apk >> $resultlog 2>&1
	sh /home/hcai/testbed/generalReport.sh \
		/home/hcai/testbed/input/pairs/$cat/$i/s.apk \
		/home/hcai/testbed/$rep/singleAppLogs_$cat/$i-s.logcat >> $resultlog 2>&1

	echo "result for $cat $i/t.apk" >> $resultlog 2>&1
	/home/hcai/bin/getpackage.sh /home/hcai/testbed/input/pairs/$cat/$i/t.apk >> $resultlog 2>&1
	sh /home/hcai/testbed/generalReport.sh \
		/home/hcai/testbed/input/pairs/$cat/$i/t.apk \
		/home/hcai/testbed/$rep/singleAppLogs_$cat/$i-t.logcat >> $resultlog 2>&1
done
mv /home/hcai/testbed/{calleerank.txt,callerrank.txt,calleerankIns.txt,callerrankIns.txt,compdist.txt,edgefreq.txt,gdistcov.txt,gdistcovIns.txt} \
	/home/hcai/testbed/results/generalReport/$rep/$cat/

exit 0
