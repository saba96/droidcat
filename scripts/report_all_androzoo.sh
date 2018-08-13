#!/bin/bash

#for year in 2016 2015 2014
: <<'END'
for year in 2012 2013 2014 2015 2016 "benign-2014" "benign-2016"
do
    echo "computing features for AndroZoo dataset --- year $year ..."
    bash allGeneralReport_malware.sh /home/hcai/Downloads/AndroZoo/$year /home/hcai/testbed/androZooLogs/$year /home/hcai/testbed/zooresults/$year
    bash allICCReport_malware.sh /home/hcai/Downloads/AndroZoo/$year /home/hcai/testbed/androZooLogs/$year /home/hcai/testbed/zooresults/$year
    bash allSecurityReport_malware.sh /home/hcai/Downloads/AndroZoo/$year /home/hcai/testbed/androZooLogs/$year /home/hcai/testbed/zooresults/$year
    bash allRankReport_malware.sh /home/hcai/Downloads/AndroZoo/$year /home/hcai/testbed/androZooLogs/$year /home/hcai/testbed/zooresults/$year
done
END

bash allGeneralReport_malware.sh /home/hcai/Downloads/AndroZoo/2011/used /home/hcai/testbed/androZooLogs/2011-new /home/hcai/testbed/zooresults/2011-new/
bash allICCReport_malware.sh /home/hcai/Downloads/AndroZoo/2011/used /home/hcai/testbed/androZooLogs/2011-new /home/hcai/testbed/zooresults/2011-new
bash allSecurityReport_malware.sh /home/hcai/Downloads/AndroZoo/2011/used /home/hcai/testbed/androZooLogs/2011-new /home/hcai/testbed/zooresults/2011-new
bash allRankReport_malware.sh /home/hcai/Downloads/AndroZoo/2011/used /home/hcai/testbed/androZooLogs/2011-new /home/hcai/testbed/zooresults/2011-new

exit 0

