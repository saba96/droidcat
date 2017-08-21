#!/bin/bash

(test $# -lt 1) && (echo "too few arguments") && exit 0

fncat=$1

root=`pwd`
outdir=$root/overallcats
mkdir -p $outdir

cats=""
while read cate;
do
    cats="$cats""$cate""    "
done < $fncat

for file in srcsink src sink callback lifecycleMethod eventHandler securityfeatures
do
    > $outdir/${file}.txt
    for cate in $cats;
    do
        for rep in firstrep secondrep thirdrep 
        do
            cat $root/$rep/$cate/${file}.txt >> $outdir/${file}.txt
        done
    done
done
exit 0
