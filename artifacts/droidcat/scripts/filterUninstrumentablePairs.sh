#!/bin/bash

srcdir=/home/hcai/testbed/input/pairs/
destdir=/home/hcai/testbed/cg.instrumented/pairs/
tgtdir=$destdir/implicit_instrumented/
#tgtdir=$destdir/explicit_instrumented/
mkdir -p $tgtdir

filter()
{
	#for subdir in "explicit" "implicit" "implicit_2ndset"
	k=1
	#for subdir in "implicit" "implicit_2ndset"
	#for subdir in "implicit_3rdset"
	#for subdir in "implicit" "implicit_2ndset" "implicit_3rdset"
	for subdir in "implicit"
	#for subdir in "explicit"
	do
		#for ((i=1;i<51;i++))
		for i in $(seq 1 250)
		do
			if [ ! -d $srcdir/$subdir/$i ];then continue; fi

			napk=`ls -l $destdir/$subdir/$i/*.apk | wc -l`

			if [ $napk -lt 2 ];then continue; fi

			mkdir -p $tgtdir/$k 
			cp -r $destdir/$subdir/$i/* $tgtdir/$k

			echo "successfully instrumented pairs: $k"

			k=`expr $k + 1`
		done
	done
}

filter

exit 0
