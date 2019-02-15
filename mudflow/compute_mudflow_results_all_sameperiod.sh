#!/bin/bash

rootdir=`pwd`

for ((i=0;i<=7;i++));
do
    unlink $rootdir/data/main_test.csv
    unlink $rootdir/data/susi_list_test.csv

    ln -s $rootdir/data/taintflows/main_test_201${i}-201${i}.csv $rootdir/data/main_test.csv
    ln -s $rootdir/data/taintflows/susi_list_201${i}-201${i}.csv $rootdir/data/susi_list_test.csv

    echo "train on year 201$i and test on year 201$i......"
    make all 2>/dev/null

    resdir=$rootdir/201${i}-201${i}
    mkdir -p $resdir
    mv $rootdir/data_main_test.txt $rootdir/Results.txt $resdir/
done
exit 0
