#!/bin/bash

root=`pwd`
outdir=$root/overall
mkdir -p $outdir
for file in gicc dataicc extraicc icclink bothdataicc icccov
do
	> $outdir/${file}.txt
	for rep in malwareLogs_firstrep malwareLogs_secondrep malwareLogs_thirdrep
	do
		cat $root/$rep/${file}.txt >> $outdir/${file}.txt
	done
done
exit 0
