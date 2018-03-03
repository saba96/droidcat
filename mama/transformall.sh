#!/bin/bash 

#for dr in benign-2017 malware-drebin malware-2013 malware-zoo-2014 malware-zoo-2015 malware-zoo-2016
#for dr in malware-2013 malware-zoo-2014 malware-zoo-2015 malware-zoo-2016

#for dr in 2010  2011  2012  2013  2017  "benign-2010"  "benign-2011"  "benign-2012"  "benign-2013"  "benign-2015"
# these data took mamadroid Feb 20 16:55 to Feb 21 23:37 to do the following - feature computation, not including call graph generation time

for dr in "benign-2014"  "benign-2016" "vs-2013"  "vs-2014"  "vs-2015"  "vs-2016"
# these data took mamadroid Feb 22 11:02 to Feb 23 14:00
do
    echo "transforming graphs/$dr ..."
    cp -r graphs/$dr graphs/$dr.org
    bash transform.sh graphs/$dr
    python MaMaStat.py -d $dr
done
exit 0

