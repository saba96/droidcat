#!/bin/bash

#(test $# -lt 1) && (echo "too few arguments") && exit 0

lowlist=${1:-'rawlow.lst'}
cat=${2:-"implicit"}
srcdir=/home/hcai/testbed/cov.instrumented/pairs.secondset/
destdir=/home/hcai/testbed/input/pairs.secondset/

reordering()
{
	cat $lowlist | while read lowapk;
	do
		pairid=${lowapk%-*}
		namerest=${lowapk#*-}

		srcp=`~/bin/getpackage.sh $srcdir/${cat}_installed/$pairid/s.apk | awk '{print $2}'`
		tgtp=`~/bin/getpackage.sh $srcdir/${cat}_installed/$pairid/t.apk | awk '{print $2}'`

		#echo "srcp=$srcp, tgtp=$tgtp"

		found=false
		for j in $(seq 1 250)
		do
			if [ ! -s $destdir/$cat/$j/s.apk ];then continue; fi
			if [ ! -s $destdir/$cat/$j/t.apk ];then continue; fi
			sp=`~/bin/getpackage.sh $destdir/$cat/$j/s.apk | awk '{print $2}'`
			tp=`~/bin/getpackage.sh $destdir/$cat/$j/t.apk | awk '{print $2}'`

			if [ $srcp != $sp ];then continue; fi
			if [ $tgtp != $tp ];then continue; fi

			echo "$j-"$namerest "for " $lowapk
			found=true
			break
		done
		if [ ! found ];then
			echo "FATAL: pair $srcdir/${cat}_installed/$pairid NOT found in $destdir/$cat/"
			exit 1
		fi
	done
}

reordering

exit 0

