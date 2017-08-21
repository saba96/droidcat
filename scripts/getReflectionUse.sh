#!/bin/bash

[ $# -ge 1 ] || exit 0
srcdir=$1

total=`ls $srcdir/*.logcat | wc -l`

n=`grep -a -E "java.lang.reflect.Method" $srcdir/*.logcat | awk -F: '{print $1}' | sort | uniq | wc -l`

echo "$n out of $total used reflection in $srcdir"
exit 0

