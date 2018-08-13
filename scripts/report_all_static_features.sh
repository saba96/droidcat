#!/bin/bash

for year in 2011 2012 2013 2017 "benign-2010" "benign-2014" "benign-2016"
do
    echo "computing features for AndroZoo dataset --- year $year ..."
    bash allStaticFeatureReport.sh /home/hcai/Downloads/AndroZoo/$year /home/hcai/testbed/androZooLogs/$year /home/hcai/testbed/zooresults/$year
done

for year in 2014 2015 2016
do
    echo "computing features for AndroZoo dataset --- year $year ..."
    bash allStaticFeatureReport.sh /home/hcai/Downloads/AndroZoo/$year /home/hcai/testbed/androZooLogs/$year /home/hcai/testbed/zooresults/$year packagename
done
exit 0

# benign 2017
bash allStaticFeatureReport.sh /home/hcai/bin/apks2017/all/  /home/hcai/testbed/catapkLogs_all/  /home/hcai/testbed/catresults/

# malware drebin
bash allStaticFeatureReport.sh /home/hcai/testbed/input/Drebin/all/  /home/hcai/testbed/DrebinLogs/   /home/hcai/testbed/drebinresults packagename

# malware 2017
bash allStaticFeatureReport.sh /home/hcai/testbed/newmalwareall   /home/hcai/testbed/newmalwareLogs_firstrep/  /home/hcai/testbed/results_newmalware.10m/  packagename

#malware 2013 
bash allStaticFeatureReport.sh /home/hcai/testbed/inputs/uniqMalware   /home/hcai/testbed/malwareLogs_highcov_10m/  /home/hcai/testbed/results_malware.highcov.10m/  packagename 0

#benign 2014
bash allStaticFeatureReport.sh /home/hcai/testbed/input/topapps   /home/hcai/testbed/singleAppLogs_benign_set1_highcov_10m/singleAppLogs_10m_implicit/  /home/hcai/testbed/results_allbenign.highcov/  packagename  0


exit 0

