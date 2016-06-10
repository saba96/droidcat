#!/bin/bash

root=`pwd`
outdir=$root/overall
mkdir -p $outdir
for file in srcsink src sink callback lifecycleMethod eventHandler 
do
	> $outdir/${file}.txt
	#for rep in first_rep second_rep third_rep 
	#for rep in malwareLogs_thirdrep malwareLogs_secondrep malwareLogs_laptop
	for rep in malwareLogs_thirdrep malwareLogs_secondrep malwareLogs_firstrep
	do
		cat $root/$rep/${file}.txt >> $outdir/${file}.txt
	done
done
exit 0
