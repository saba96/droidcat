#!/bin/bash

(test $# -lt 1) && (echo "too few arguments") && exit 0

srcdir=/home/hcai/testbed/input/pairs/$1
destdir=/home/hcai/testbed/cg.instrumented/pairs/$1
mkdir -p $destdir

instr()
{
	for orgapk in $srcdir/*.apk
	do
		/home/hcai/testbed/cgInstr.sh $orgapk "$destdir"
	done
}

sign()
{
	for instredapk in $destdir/*.apk
	do
		echo "chapple" | /home/hcai/testbed/signandalign.sh $instredapk
	done
}

instr

#sign

exit 0
