#!/bin/bash

root=`pwd`
outdir=$root/overall
mkdir -p $outdir
for file in gicc dataicc extraicc icclink bothdataicc icccov
do
	> $outdir/${file}.txt
	for rep in results_allbenign.highcov results_benign3rd.highcov
	do
		cat /home/hcai/testbed/$rep/ICCReport/overall/${file}.txt >> $outdir/${file}.txt
	done
done
exit 0
