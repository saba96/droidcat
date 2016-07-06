#!/bin/bash

(test $# -lt 0) && (echo "too few arguments") && exit 0

#rep=${1:-"singleAppLogs_benign_set3_highcov"}
rep=${1:-"singleAppLogs_benign_set3_highcov_10m"}
TRACEDIR=/home/hcai/testbed/$rep/

#resultdir=/home/hcai/testbed/results_benign3rd.highcov/ICCReport
resultdir=/home/hcai/testbed/results_benign3rd.highcov.10m/ICCReport
mkdir -p $resultdir $resultdir/overall
resultlog=$resultdir/log.ICCReport.all
> $resultlog

for ((i=1;i<=515;i++))
do
	if [ ! -s $TRACEDIR/${i}.apk.logcat ];
	then
		continue
	fi
	rt=`cat lowcov_benign_set3 | awk '{print $1}' | grep -a -c "^${i}.apk.logcat$"`
	if [ $rt -lt 1 ];then
		echo "result for ${i}.apk" >> $resultlog 2>&1
		/home/hcai/bin/getpackage.sh /home/hcai/testbed/input/pairs/${i}.apk >> $resultlog 2>&1
		sh /home/hcai/testbed/ICCReport.sh \
			/home/hcai/testbed/input/pairs/${i}.apk \
			$TRACEDIR/${i}.apk.logcat >> $resultlog 2>&1
	fi
done
mv /home/hcai/testbed/{gicc.txt,dataicc.txt,extraicc.txt,icclink.txt,icccov.txt,bothdataicc.txt} $resultdir/overall 
mv /home/hcai/testbed/iccfeatures.txt $resultdir/

exit 0
