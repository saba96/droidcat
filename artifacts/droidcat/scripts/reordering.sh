#!/bin/bash

#(test $# -lt 1) && (echo "too few arguments") && exit 0

destdir=/home/hcai/testbed/input/pairs/
srcdir=/home/hcai/testbed/cg.instrumented/pairs/

reordering()
{
	for subdir in "explicit" "implicit"
	do
		for i in $(seq 1 250)
		do
			if [ ! -s $srcdir/${subdir}_installed/$i/s.apk ];then continue; fi
			if [ ! -s $srcdir/${subdir}_installed/$i/t.apk ];then continue; fi

			srcp=`~/bin/getpackage.sh $srcdir/${subdir}_installed/$i/s.apk | awk '{print $2}'`
			tgtp=`~/bin/getpackage.sh $srcdir/${subdir}_installed/$i/t.apk | awk '{print $2}'`

			echo "srcp=$srcp, tgtp=$tgtp"

			tdir=$destdir/tmp/$subdir/$i
			for j in $(seq 1 250)
			do
				if [ ! -s $destdir/$subdir/$j/s.apk ];then continue; fi
				if [ ! -s $destdir/$subdir/$j/t.apk ];then continue; fi
				sp=`~/bin/getpackage.sh $destdir/$subdir/$j/s.apk | awk '{print $2}'`
				tp=`~/bin/getpackage.sh $destdir/$subdir/$j/t.apk | awk '{print $2}'`

				if [ $srcp != $sp ];then continue; fi
				if [ $tgtp != $tp ];then continue; fi

				#if [[ $srcp = $sp && $tgtp = $tp ]];then
				mkdir -p $tdir
				cp $destdir/$subdir/$j/*.apk $tdir/
				break
				#fi
			done
			if [ ! -d $tdir ];then
				echo "FATAL: pair $srcdir/${subdir}_installed/$i NOT found in $destdir/$subdir/"
				exit 1
			fi
		done
	done
}

reordering

exit 0

