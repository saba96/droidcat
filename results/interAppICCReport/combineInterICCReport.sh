#!/bin/bash

root=`pwd`
outdir=$root/overall
mkdir -p $outdir
for file in gicc dataicc extraicc icclink bothdataicc pairicc
do
	> $outdir/${file}.txt
	for rep in first_rep second_rep third_rep 
	do
		for ct in explicit implicit
		do
			cat $root/$rep/$ct/${file}.txt >> $outdir/${file}.txt
		done
	done
done
exit 0
