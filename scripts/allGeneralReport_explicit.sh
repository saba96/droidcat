#!/bin/bash

#(test $# -lt 1) && (echo "too few arguments") && exit 0

tmv=${1:-"3600"}
APKDIR=/home/hcai/input/pairs/explicit/
TRACEDIR=/home/hcai/testbed/first_rep/singleAppLogs_explicit

resultlog=/home/hcai/testbed/log.generalReport.all.explicit
> $resultlog
for ((i=1;i<=7;i++))
do
	echo "result for explicit $i/s.apk" >> $resultlog
	/home/hcai/bin/getpackage.sh /home/hcai/testbed/input/pairs/explicit/$i/s.apk >> $resultlog
	sh /home/hcai/testbed/generalReport.sh \
		/home/hcai/testbed/input/pairs/explicit/$i/s.apk \
		/home/hcai/testbed/first_rep/singleAppLogs_explicit/$i-s.logcat >> $resultlog

	echo "result for explicit $i/t.apk" >> $resultlog
	/home/hcai/bin/getpackage.sh /home/hcai/testbed/input/pairs/explicit/$i/t.apk >> $resultlog
	sh /home/hcai/testbed/generalReport.sh \
		/home/hcai/testbed/input/pairs/explicit/$i/t.apk \
		/home/hcai/testbed/first_rep/singleAppLogs_explicit/$i-t.logcat >> $resultlog
done
exit 0
