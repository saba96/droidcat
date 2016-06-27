#!/bin/bash

root=`pwd`
outdir=$root/overall
mkdir -p $outdir
for file in calleerank callerrank calleerankIns callerrankIns compdist edgefreq gdistcov gdistcovIns 
do
	> $outdir/${file}.txt
	#for rep in malwareLogs_laptop malwareLogs_secondrep malwareLogs_thirdrep
	for rep in malwareLogs_firstrep malwareLogs_secondrep malwareLogs_thirdrep
	do
		cat $root/$rep/${file}.txt >> $outdir/${file}.txt
	done
done
exit 0
