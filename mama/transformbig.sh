#!/bin/bash 

#for dr in benign-2017 malware-drebin malware-2013 malware-zoo-2014 malware-zoo-2015 malware-zoo-2016
#for dr in malware-2013 malware-zoo-2014 malware-zoo-2015 malware-zoo-2016
#for dr in malware-drebin
#do
#    echo "transforming graphs/$dr ..."
#    cp -r graphs/$dr graphs/$dr.org
#    bash transform.sh graphs/$dr
#done

for dr in benign-2017 malware-drebin
do
    part=1
    fcnt=0
    cursubdir=graphs/${dr}-part$part
    mkdir -p $cursubdir
    for apktxt in graphs/$dr/*.apk.txt
    do
        ((fcnt++))
        cp -r $apktxt $cursubdir
        if [ $fcnt -ge 200 ];then
            fcnt=0
            python MaMaStat.py -c 8 -d ${dr}-part$part
            ((part++))
            cursubdir=graphs/${dr}-part$part
            mkdir -p $cursubdir
        fi
    done
done

exit 0

