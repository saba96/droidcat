#!/bin/bash

(test $# -lt 2) && (echo "too few arguments") && exit 0

rep=${1}
cat=${2}
APKDIR=/home/hcai/bin/apks2017/$cat/
TRACEDIR=/home/hcai/testbed/catapkLogs_$rep

resultdir=/home/hcai/testbed/catresults/securityReport/$rep
mkdir -p $resultdir $resultdir/$cat
resultlog=$resultdir/log.securityReport.all.$cat
> $resultlog
for apk in $APKDIR/*.apk
do
	echo "result for $apk" >> $resultlog 2>&1
    apkself=${apk##*/}
	/home/hcai/bin/getpackage.sh $apk >> $resultlog 2>&1
	sh /home/hcai/testbed/securityReport.sh \
        $apk \
		$TRACEDIR/$cat/$apkself.logcat >> $resultlog 2>&1

done

mv /home/hcai/testbed/{srcsink.txt,src.txt,sink.txt,callback.txt,lifecycleMethod.txt,eventHandler.txt} $resultdir/$cat
mv /home/hcai/testbed/securityfeatures.txt $resultdir/$cat/

exit 0
