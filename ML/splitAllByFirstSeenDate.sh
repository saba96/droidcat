#!/bin/bash

rootdir=features_droidcat_byfirstseen
mkdir -p $rootdir

for ((i=0;i<=6;i++))
do
    for fn in gfeatures iccfeatures securityfeatures 
    do
        python splitByFirstSeen.py firstseendates/firstseen-zoobenign201$i.txt features_droidcat/zoobenign201$i/$fn.txt new-zoobenign 201$i

        for d in new-zoobenign*
        do
            dstdir=$rootdir/${d##*-}
            mkdir -p $dstdir
            cat $d >> $dstdir/$fn.txt
        done
        rm new-zoobenign*
    done
done

for ((i=0;i<=7;i++))
do
    for fn in gfeatures iccfeatures securityfeatures 
    do
        python splitByFirstSeen.py firstseendates/firstseen-zoo201$i.txt features_droidcat/zoo201$i/$fn.txt new-zoo 201$i

        for d in new-zoo*
        do
            dstdir=$rootdir/${d##*-}
            mkdir -p $dstdir
            cat $d >> $dstdir/$fn.txt
        done
        rm new-zoo*
    done
done

for ((i=3;i<=6;i++))
do
    for fn in gfeatures iccfeatures securityfeatures 
    do
        python splitByFirstSeen.py firstseendates/firstseen-vs201$i.txt features_droidcat/vs201$i/$fn.txt new-vs 201$i

        for d in new-vs*
        do
            dstdir=$rootdir/${d##*-}
            mkdir -p $dstdir
            cat $d >> $dstdir/$fn.txt
        done
        rm new-vs*
    done
done

for i in 4 7
do
    for fn in gfeatures iccfeatures securityfeatures 
    do
        python splitByFirstSeen.py firstseendates/firstseen-benign201$i.txt features_droidcat/benign201$i/$fn.txt new-benign 201$i

        for d in new-benign*
        do
            dstdir=$rootdir/${d##*-}
            mkdir -p $dstdir
            cat $d >> $dstdir/$fn.txt
        done
        rm new-benign*
    done
done

for i in 3 7
do
    for fn in gfeatures iccfeatures securityfeatures 
    do
        python splitByFirstSeen.py firstseendates/firstseen-malware201$i.txt features_droidcat/malware201$i/$fn.txt new-malware 201$i

        for d in new-malware*
        do
            dstdir=$rootdir/${d##*-}
            mkdir -p $dstdir
            cat $d >> $dstdir/$fn.txt
        done
        rm new-malware*
    done
done

for fn in gfeatures iccfeatures securityfeatures 
do
    python splitByFirstSeen.py firstseendates/firstseen-drebin.txt features_droidcat/malware-drebin/$fn.txt new-malware-drebin 2013

    for d in new-malware-drebin*
    do
        dstdir=$rootdir/${d##*-}
        mkdir -p $dstdir
        cat $d >> $dstdir/$fn.txt
    done
    rm new-malware-drebin*
done


