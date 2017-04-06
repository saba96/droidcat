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

resultdir=/home/hcai/testbed/results/securityReport/$rep
mkdir -p $resultdir $resultdir/$cat
resultlog=$resultdir/log.securityReport.all.$cat
> $resultlog
for ((i=1;i<=${pairs};i++))
do
	echo "result for $cat $i/s.apk" >> $resultlog 2>&1
	/home/hcai/bin/getpackage.sh /home/hcai/testbed/input/pairs/$cat/$i/s.apk >> $resultlog 2>&1
	pn=`/home/hcai/bin/getpackage.sh /home/hcai/testbed/input/pairs/$cat/$i/s.apk`
	# these are actually detected as malicious by VirusTotal
	if [ "$pn" = "com.ictap.casm" ];then continue;fi
	if [ "$pn" = "com.aob" ];then continue;fi
	if [ "$pn" = "com.vaishnavism.vishnusahasranaamam.english" ];then continue;fi
	if [ "$pn" = "com.hardcoreapps.loboshaker" ];then continue;fi

	sh /home/hcai/testbed/securityReport.sh \
		/home/hcai/testbed/input/pairs/$cat/$i/s.apk \
		/home/hcai/testbed/$rep/singleAppLogs_$cat/$i-s.logcat >> $resultlog 2>&1
done

for ((j=1;j<=${pairs};j++))
do
	echo "result for $cat $j/t.apk" >> $resultlog 2>&1
	pn=`/home/hcai/bin/getpackage.sh /home/hcai/testbed/input/pairs/$cat/$j/t.apk`
	# these are actually detected as malicious by VirusTotal
	if [ "$pn" = "com.ictap.casm" ];then continue;fi
	if [ "$pn" = "com.aob" ];then continue;fi
	if [ "$pn" = "com.vaishnavism.vishnusahasranaamam.english" ];then continue;fi
	if [ "$pn" = "com.hardcoreapps.loboshaker" ];then continue;fi
	/home/hcai/bin/getpackage.sh /home/hcai/testbed/input/pairs/$cat/$j/t.apk >> $resultlog 2>&1
	sh /home/hcai/testbed/securityReport.sh \
		/home/hcai/testbed/input/pairs/$cat/$j/t.apk \
		/home/hcai/testbed/$rep/singleAppLogs_$cat/$j-t.logcat >> $resultlog 2>&1
done

mv /home/hcai/testbed/{srcsink.txt,src.txt,sink.txt,callback.txt,lifecycleMethod.txt,eventHandler.txt} \
	/home/hcai/testbed/results/securityReport/$rep/$cat/

exit 0
