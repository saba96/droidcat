#!/bin/bash

#(test $# -lt 1) && (echo "too few arguments") && exit 0

tmv=${1:-"3600"}
APKDIR=/home/hcai/input/pairs/implicit/
TRACEDIR=/home/hcai/testbed/first_rep/singleAppLogs_implicit

resultlog=/home/hcai/testbed/log.ICCReport.all.implicit
> $resultlog
for ((i=1;i<=54;i++))
do
	echo "result for implicit $i/s.apk" >> $resultlog 2>&1
	/home/hcai/bin/getpackage.sh /home/hcai/testbed/input/pairs/implicit/$i/s.apk >> $resultlog 2>&1
	sh /home/hcai/testbed/ICCReport.sh \
		/home/hcai/testbed/input/pairs/implicit/$i/s.apk \
		/home/hcai/testbed/first_rep/singleAppLogs_implicit/$i-s.logcat >> $resultlog 2>&1

	echo "result for implicit $i/t.apk" >> $resultlog 2>&1
	/home/hcai/bin/getpackage.sh /home/hcai/testbed/input/pairs/implicit/$i/t.apk >> $resultlog 2>&1
	sh /home/hcai/testbed/ICCReport.sh \
		/home/hcai/testbed/input/pairs/implicit/$i/t.apk \
		/home/hcai/testbed/first_rep/singleAppLogs_implicit/$i-t.logcat >> $resultlog 2>&1
done
exit 0
