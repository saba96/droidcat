#!/bin/bash

for year in 2013 2014 2015
do
    echo "computing features for Virusshare dataset --- year $year ..."
    bash allGeneralReport_malware.sh /home/hcai/Downloads/VirusShare/$year /home/hcai/testbed/virusShareLogs/$year /home/hcai/testbed/vsresults/$year
    bash allICCReport_malware.sh /home/hcai/Downloads/VirusShare/$year /home/hcai/testbed/virusShareLogs/$year /home/hcai/testbed/vsresults/$year
    bash allSecurityReport_malware.sh /home/hcai/Downloads/VirusShare/$year /home/hcai/testbed/virusShareLogs/$year /home/hcai/testbed/vsresults/$year
done

exit 0

