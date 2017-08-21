#!/bin/bash

(test $# -lt 0) && (echo "too few arguments") && exit 0

rep=${1:-"ContagioLogs"}
TRACEDIR=/home/hcai/testbed/$rep/

resultdir=/home/hcai/testbed/contagioResults/ICCReport
mkdir -p $resultdir
resultlog=$resultdir/log.ICCReport.all
> $resultlog

resultidx=$resultdir/idx.ICCReport
> $resultidx

for apkname in /home/hcai/testbed/input/Contagio/*.apk
do
    j=${apkname##*/}
    i=${j%.*}
	if [ ! -s $TRACEDIR/${i}.apk.logcat ];
	then
		continue
	fi
	#rt=`cat lowcov_malware | awk '{print $1}' | grep -a -c "^${i}.apk.logcat$"`
	#if [ $rt -lt 1 ];then
		echo "result for ${i}.apk" >> $resultlog 2>&1
		/home/hcai/bin/getpackage.sh /home/hcai/testbed/cg.instrumented/Contagio/org/${i}-org.apk >> $resultlog 2>&1
		sh /home/hcai/testbed/ICCReport.sh \
			/home/hcai/testbed/cg.instrumented/Contagio/org/${i}-org.apk \
			$TRACEDIR/${i}.apk.logcat >> $resultlog 2>&1
		echo "$i" >> $resultidx
	#fi
done
mv /home/hcai/testbed/{gicc.txt,dataicc.txt,extraicc.txt,icclink.txt,icccov.txt,bothdataicc.txt} $resultdir/
mv /home/hcai/testbed/iccfeatures.txt $resultdir/

exit 0
