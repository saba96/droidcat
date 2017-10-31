#!/bin/bash

destdir=/home/hcai/testbed/cg.instrumented/PraguardMalgenome

>log.instr.praguardgenome
instr()
{
	mkdir -p $destdir/tmp/
	i=1
	for orgapk in /home/hcai/testbed/input/PraguardMalgenome/*.apk
	do
        apkname=${orgapk##*/}
        if [ -s $destdir/${apkname} ];
        then
            echo "$destdir/${apkname}.apk already processed, skip it"
            ((i++))
            continue
        fi
		/home/hcai/testbed/cgInstr.sh $orgapk $destdir/ 2>/dev/null 1>>log.instr.praguardgenome
		cp /home/hcai/testbed/input/PraguardMalgenome/${apkname} $destdir/${apkname}-org.apk
		((i++))
	done
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
