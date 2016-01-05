#!/bin/bash

for i in $@
do
	res=`aapt list -a $i | grep -E "(^Package Group)*(packageCount=1 name=)"`
	echo -e $i"\t"${res##*=}
	#echo ${res##*=}
done
