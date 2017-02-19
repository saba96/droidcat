#!/bin/bash

root=`pwd`
outdir=$root/overall
mkdir -p $outdir
for file in calleerank callerrank calleerankIns callerrankIns compdist edgefreq gdistcov gdistcovIns 
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
