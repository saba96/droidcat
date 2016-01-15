#!/bin/bash

destdir=/home/hcai/testbed/cg.instrumented/pairs/
tgtdir=$destdir/explicit_instrumented/
#tgtdir=$destdir/implicit_instrumented/
finaldir=$destdir/explicit_installed
#finaldir=$destdir/implicit_installed
mkdir -p $finaldir

tryInstall()
{
	k=1
	for i in $(seq 1 100)
	do
		if [ ! -d $tgtdir/$i ];then continue; fi

		ret=`apkinstall $tgtdir/$i/s.apk`
		n1=`echo $ret | grep -a -c "Success"`
		if [ $n1 -lt 1 ];then continue; fi
		apkuninstall $tgtdir/$i/s.apk

		ret=`apkinstall $tgtdir/$i/t.apk`
		n2=`echo $ret | grep -a -c "Success"`
		if [ $n2 -lt 1 ];then continue; fi
		apkuninstall $tgtdir/$i/t.apk

		mkdir -p $finaldir/$k 
		cp -r $tgtdir/$i/* $finaldir/$k

		echo "successfully installed instrumented pairs: $k"

		k=`expr $k + 1`
	done
}

tryInstall

exit 0
