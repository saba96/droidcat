#!/bin/bash

(test $# -lt 1) && (echo "too few arguments") && exit 0

fncat=$1

root=`pwd`
outdir=$root/overallreps
mkdir -p $outdir

cats=""
while read cate;
do
    cats="$cats""$cate""    "
done < $fncat

for cate in $cats;
do
    mkdir -p $outdir/$cate
    for file in calleerank callerrank calleerankIns callerrankIns compdist edgefreq gdistcov gdistcovIns gfeatures
    do
        > $outdir/$cate/${file}.txt
        for rep in firstrep secondrep thirdrep 
        do
            cat $root/$rep/$cate/${file}.txt >> $outdir/$cate/${file}.txt
        done
    done
done
exit 0
