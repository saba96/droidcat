#!/bin/bash

(test $# -lt 3) && (echo "too few arguments") && exit 0

APKDIR=$1
TRACEDIR=$2
RESULTDIR=$3
FEATUREKEY=${4:-"apkname"}
checklog=${5:-"1"}

mkdir -p $RESULTDIR/staticFeatureReport
resultlog=$RESULTDIR/staticFeatureReport/log.staticFeatureReport.all
> $resultlog
for orgapk in $APKDIR/*.apk
do
    packname=${orgapk##*/}

    if [ $checklog -ge 1 ];then
        if [ ! -s $TRACEDIR/$packname.logcat ];
        then
            continue
        fi
    fi

    echo "result for $orgapk" >> $resultlog 2>&1
    /home/hcai/bin/getpackage.sh $orgapk >> $resultlog 2>&1
    sh /home/hcai/testbed/staticFeatureReport.sh \
        $orgapk $RESULTDIR/staticFeatureReport $FEATUREKEY >> $resultlog 2>&1
done

exit 0

