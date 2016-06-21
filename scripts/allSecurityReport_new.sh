#!/bin/bash

(test $# -lt 1) && (echo "too few arguments") && exit 0

rep=${1:-"benign-new-firstrep"}
cat=${2:-"implicit"}
APKDIR=/home/hcai/testbed/input/pairs/$cat/
TRACEDIR=/home/hcai/testbed/$rep/singleAppLogsNew_$cat

resultdir=/home/hcai/testbed/results.benignNew/securityReport/$rep
mkdir -p $resultdir $resultdir/$cat
resultlog=$resultdir/log.securityReport.all.$cat
> $resultlog
for ((i=1;i<=250;i++))
do
	if [ ! -s $APKDIR/$i/s.apk ];then continue; fi
	if [ ! -s $APKDIR/$i/t.apk ];then continue; fi
	
	echo "result for $cat $i/s.apk" >> $resultlog 2>&1
	/home/hcai/bin/getpackage.sh $APKDIR/$i/s.apk >> $resultlog 2>&1
	sh /home/hcai/testbed/securityReport.sh \
		$APKDIR/$i/s.apk \
		$TRACEDIR/$i-s.logcat >> $resultlog 2>&1

	echo "result for $cat $i/t.apk" >> $resultlog 2>&1
	/home/hcai/bin/getpackage.sh $APKDIR/$i/t.apk >> $resultlog 2>&1
	sh /home/hcai/testbed/securityReport.sh \
		$APKDIR/$i/t.apk \
		$TRACEDIR/$i-t.logcat >> $resultlog 2>&1
done
mv /home/hcai/testbed/{srcsink.txt,src.txt,sink.txt,callback.txt,lifecycleMethod.txt,eventHandler.txt} $resultdir/$cat
mv /home/hcai/testbed/securityfeatures.txt $resultdir/$cat/

exit 0
