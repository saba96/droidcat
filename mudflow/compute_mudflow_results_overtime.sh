#!/bin/bash

rootdir=`pwd`

oneTest()
{
        i=$1
        j=$2
        #echo $i, $j
        unlink $rootdir/data/main_test.csv
        unlink $rootdir/data/susi_list_test.csv

        ln -s $rootdir/data/taintflows/main_test_201${i}-201${j}.csv $rootdir/data/main_test.csv
        ln -s $rootdir/data/taintflows/susi_list_201${i}-201${j}.csv $rootdir/data/susi_list_test.csv

        echo "train on year 201$i and test on year 201$j......"
        make all 2>/dev/null

        resdir=$rootdir/201${i}-201${j}
        mkdir -p $resdir
        mv $rootdir/data_main_test.txt $rootdir/Results.txt $resdir/
}

oneTest 6 7
exit 0

for ((i=0;i<=6;i++));
do
    for ((j=i+1;j<=7;j++));
    do
        oneTest $i $j
    done
done
exit 0
