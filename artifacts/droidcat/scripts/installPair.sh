#!/bin/bash

(test $# -lt 1) && (echo "too few arguments") && exit 0

srcdir=/home/hcai/testbed/input/pairs/$1
destdir=/home/hcai/testbed/cg.instrumented/pairs/$1
mkdir -p $destdir

install()
{
	for orgapk in $srcdir/*.apk
	do
		adb install $orgapk
	done
}

install 

exit 0
