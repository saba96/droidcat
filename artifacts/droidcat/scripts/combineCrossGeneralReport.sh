#!/bin/bash

root=`pwd`
outdir=$root/overall
mkdir -p $outdir
for file in calleerank callerrank calleerankIns callerrankIns compdist edgefreq gdistcov gdistcovIns 
do
	> $outdir/${file}.txt
	for rep in results.highcov results.benignNew.highcov
	do
		cat /home/hcai/testbed/$rep/generalReport/overall/${file}.txt >> $outdir/${file}.txt
	done
done
exit 0
