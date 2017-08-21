#!/bin/bash

destdir=/home/hcai/testbed/cg.instrumented/Contagio/

instr()
{
	mkdir -p $destdir/tmp/
	i=1
	for orgapk in /home/hcai/testbed/input/Contagio/*.apk
	do
        if [ -s $destdir/${i}.apk ];
        then
            echo "$destdir/${i}.apk already processed, skip it"
            ((i++))
            continue
        fi
		/home/hcai/testbed/cgInstr.sh $orgapk $destdir/tmp/
		mv $destdir/tmp/*.apk $destdir/${i}.apk
		cp /home/hcai/testbed/input/Contagio/${orgapk##*/}.result $destdir/${i}.apk.result
		cp /home/hcai/testbed/input/Contagio/${orgapk##*/} $destdir/${i}-org.apk
		rm -f $destdir/tmp/*
		((i++))
	done
	rm -rf $destdir/tmp
}

sign()
{
	for instredapk in $destdir/*.apk
	do
		echo "chapple" | /home/hcai/testbed/signandalign.sh $instredapk
	done
}

instr

#sign

exit 0
