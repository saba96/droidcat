#!/bin/bash 

for i in `seq 1 237`
do
    md5=`md5sum ~/testbed/input/Contagio/ZZContagio${i}.apk | awk '{print $1}'`
    mv ~/testbed/input/Contagio/ZZContagio${i}.apk ~/testbed/input/Contagio/$md5.apk
    mv ~/testbed/input/Contagio/ZZContagio${i}.apk.result ~/testbed/input/Contagio/$md5.apk.result

    mv ~/testbed/cg.instrumented/Contagio/${i}.apk ~/testbed/cg.instrumented/Contagio/$md5.apk
    mv ~/testbed/cg.instrumented/Contagio/${i}.apk.result ~/testbed/cg.instrumented/Contagio/$md5.apk.result
    mv ~/testbed/cg.instrumented/Contagio/org/${i}-org.apk ~/testbed/cg.instrumented/Contagio/org/${md5}-org.apk

    mv ~/testbed/ContagioLogs/${i}.apk.logcat ~/testbed/ContagioLogs/$md5.apk.logcat
    mv ~/testbed/ContagioLogs/${i}.apk.monkey ~/testbed/ContagioLogs/$md5.apk.monkey
done

exit 0
