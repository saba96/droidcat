#!/bin/bash

(test $# -lt 1) && (echo "too few arguments") && exit 0
pn=$1
destdir=/home/hcai/testbed/cg.instrumented/pairs/
finaldir=$destdir/implicit_installed

uninstall()
{
	apkuninstall $finaldir/$pn/s.apk
	apkuninstall $finaldir/$pn/t.apk
}

uninstall 

echo "app pair no. $pn has been uninstalled successfully."

exit 0
