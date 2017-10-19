#!/bin/bash 

#for dr in benign-2017 malware-drebin malware-2013 malware-zoo-2014 malware-zoo-2015 malware-zoo-2016
for dr in malware-2013 malware-zoo-2014 malware-zoo-2015 malware-zoo-2016
do
    echo "transforming graphs/$dr ..."
    cp -r graphs/$dr graphs/$dr.org
    bash transform.sh graphs/$dr
    python MaMaStat.py -d $dr
done
exit 0

