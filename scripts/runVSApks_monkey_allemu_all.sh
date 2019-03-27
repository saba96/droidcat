#!/bin/bash 
timeout() {

    time=$1

    # start the command in a subshell to avoid problem with pipes
    # (spawn accepts one command)
    command="/bin/sh -c \"$2\""

    expect -c "set echo \"-noecho\"; set timeout $time; spawn -noecho $command; expect timeout { exit 1 } eof { exit 0 }"    

    if [ $? = 1 ] ; then
        echo "Timeout after ${time} seconds"
    fi

}


#bash runVSApks_monkey_allemu.sh 60 5550 Nexus-One-21 2013 21 1>>log.vs2013.api21 2>&1 &
#bash runVSApks_monkey_allemu.sh 60 5552 Nexus-One-22 2013 22 1>>log.vs2013.api22 2>&1 &
#bash runVSApks_monkey_allemu.sh 60 5554 Nexus-One-23 2013 23 1>>log.vs2013.api23 2>&1 &
#bash runVSApks_monkey_allemu.sh 60 5556 Nexus-One-24 2013 24 1>>log.vs2013.api24 2>&1 &
#bash runVSApks_monkey_allemu.sh 60 5558 Nexus-One-25 2013 25 1>>log.vs2013.api25 2>&1 &

#bash runVSApks_monkey_allemu.sh 60 5560 Nexus-One-21-2 2014 21 1>>log.vs2014.api21 2>&1 &
#bash runVSApks_monkey_allemu.sh 60 5562 Nexus-One-22-2 2014 22 1>>log.vs2014.api22 2>&1 &
#bash runVSApks_monkey_allemu.sh 60 5564 Nexus-One-23-2 2014 23 1>>log.vs2014.api23 2>&1 &
#bash runVSApks_monkey_allemu.sh 60 5566 Nexus-One-24-2 2014 24 1>>log.vs2014.api24 2>&1 &
#bash runVSApks_monkey_allemu.sh 60 5568 Nexus-One-25-2 2014 25 1>>log.vs2014.api25 2>&1 &

#bash runVSApks_monkey_allemu.sh 60 5570 Nexus-One-21-3 2015 21 1>>log.vs2015.api21 2>&1 &
#bash runVSApks_monkey_allemu.sh 60 5572 Nexus-One-22-3 2015 22 1>>log.vs2015.api22 2>&1 &
#bash runVSApks_monkey_allemu.sh 60 5574 Nexus-One-23-3 2015 23 1>>log.vs2015.api23 2>&1 &
bash runVSApks_monkey_allemu.sh 60 5560 Nexus-One-24-3 2015 24 1>>log.vs2015.api24 2>&1 &
#bash runVSApks_monkey_allemu.sh 60 5562 Nexus-One-25-3 2015 25 1>>log.vs2015.api25 2>&1 &

#bash runVSApks_monkey_allemu.sh 60 5576 Nexus-One-21 2016 21 1>>log.vs2016.api21 2>&1 &
#bash runVSApks_monkey_allemu.sh 60 5578 Nexus-One-22 2016 22 1>>log.vs2016.api22 2>&1 &
#bash runVSApks_monkey_allemu.sh 60 5564 Nexus-One-23 2016 23 1>>log.vs2016.api23 2>&1 &
#bash runVSApks_monkey_allemu.sh 60 5566 Nexus-One-24 2016 24 1>>log.vs2016.api24 2>&1 &
#bash runVSApks_monkey_allemu.sh 60 5568 Nexus-One-25 2016 25 1>>log.vs2016.api25 2>&1 &

