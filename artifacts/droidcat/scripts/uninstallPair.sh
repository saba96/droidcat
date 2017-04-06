#!/bin/bash

(test $# -lt 1) && (echo "too few arguments") && exit 0

srcdir=/home/hcai/testbed/input/pairs/$1
destdir=/home/hcai/testbed/cg.instrumented/pairs/$1
mkdir -p $destdir

uninstall()
{
	for apk in $srcdir/*.apk
	do
		echo "uninstall $apk..."
		res=`aapt list -a $apk | grep -E "(^Package Group)*(packageCount=1 name=)"`
		adb uninstall ${res##*=}
	done
}

uninstall 

exit 0
