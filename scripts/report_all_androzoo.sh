#!/bin/bash

for year in 2016 2015 2014
do
    echo "computing features for AndroZoo dataset --- year $year ..."
    bash allGeneralReport_malware.sh /home/hcai/Downloads/AndroZoo/$year /home/hcai/testbed/androZooLogs/$year /home/hcai/testbed/zooresults/$year
    bash allICCReport_malware.sh /home/hcai/Downloads/AndroZoo/$year /home/hcai/testbed/androZooLogs/$year /home/hcai/testbed/zooresults/$year
    bash allSecurityReport_malware.sh /home/hcai/Downloads/AndroZoo/$year /home/hcai/testbed/androZooLogs/$year /home/hcai/testbed/zooresults/$year
done

exit 0
