#!/bin/bash

#for year in 2010 2011 2017 "benign-2010" "benign-2011" "benign-2012" "benign-2013" "benign-2015"
for year in $@
do
    echo "computing trace statistics for AndroZoo dataset --- year $year ..."
    #sshfs -o reconnect ${OPT9010}:/home/hcai  /home/hcai/opt9010
    #bash allGeneralReport.sh /home/hcai/Downloads/AndroZoo/$year /home/hcai/testbed/sapienzAndroZooLogs/$year /home/hcai/testbed/zooresults_sapienz/$year

    #sshfs -o reconnect ${OPT9010}:/home/hcai  /home/hcai/opt9010
    bash allICCReport.sh /home/hcai/Downloads/AndroZoo/$year /home/hcai/testbed/sapienzAndroZooLogs/$year /home/hcai/testbed/zooresults_sapienz/$year

    #sshfs -o reconnect ${OPT9010}:/home/hcai  /home/hcai/opt9010
    bash allSecurityReport.sh /home/hcai/Downloads/AndroZoo/$year /home/hcai/testbed/sapienzAndroZooLogs/$year /home/hcai/testbed/zooresults_sapienz/$year

    #sshfs -o reconnect ${OPT9010}:/home/hcai  /home/hcai/opt9010
    bash allRankReport.sh /home/hcai/Downloads/AndroZoo/$year /home/hcai/testbed/sapienzAndroZooLogs/$year /home/hcai/testbed/zooresults_sapienz/$year
done

exit 0


