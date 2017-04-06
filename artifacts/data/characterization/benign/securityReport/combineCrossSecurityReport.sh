#!/bin/bash

root=`pwd`
outdir=$root/overall
mkdir -p $outdir
for file in srcsink src sink callback lifecycleMethod eventHandler 
do
	> $outdir/${file}.txt
	for rep in results.highcov.10m results_benign3rd.highcov.10m results.benignNew.highcov.10m
	do
		cat /home/hcai/testbed/$rep/securityReport/overall/${file}.txt >> $outdir/${file}.txt
	done
done
exit 0
