#!/bin/bash

(test $# -lt 1) && (echo "too few arguments") && exit 0

pn=$1
destdir=/home/hcai/testbed/cg.instrumented/pairs/
#finaldir=$destdir/implicit_installed
finaldir=$destdir/explicit_installed

install()
{
	apkinstall $finaldir/$pn/s.apk
	apkinstall $finaldir/$pn/t.apk
}

install 

echo "app pair no. $pn has been installed successfully."

exit 0
