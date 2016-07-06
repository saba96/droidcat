#!/bin/bash

root=`pwd`
outdir=$root/overall
mkdir -p $outdir
for file in srcsink src sink callback lifecycleMethod eventHandler 
do
	> $outdir/${file}.txt
	for rep in results.highcov results.benignNew.highcov
	do
		cat /home/hcai/testbed/$rep/securityReport/overall/${file}.txt >> $outdir/${file}.txt
	done
done
exit 0
