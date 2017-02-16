#!/bin/bash

(test $# -lt 1) && (echo "too few arguments") && exit 0
fnlist=$1
total=${2:-"250"}
start=${3:-"1"}

szlimit=`expr 10 "*" 1024 "*" 1024`
checkapk()
{
	[[ $# -lt 1 ]] && return 0
	apk=$1
	sdk=$(gettargetsdk.sh "$apk")
	echo "target sdk="$sdk
	if [[ sdk -lt 0x13 ]];then
		sdk=$(getminsdk.sh "$apk")
		echo "min sdk="$sdk
		[[ sdk -lt 0x13 ]] && return 0
	fi
	size=$(stat -c%s "$apk")
	echo "size="$size
	[[ size -gt szlimit ]] && return 0 
	return 1
}

OUTDIR=`pwd`/newpairs
mkdir -p $OUTDIR

> /home/hcai/bin/newpairs.lst
pc=$start
while ((pc <= total))
do
	for sln in `sort -R $fnlist | tail -n 200 | awk '{print $1}'`
	do
		echo "===== try downloading pair no. $pc ====="
		#line=`echo "$sln" | cut -d' ' -f1`
		line="$sln"
		srcapp=${line%%-*}
		tgtapp=${line##*>}

		# skip ones already used before
		cnt=`cat /home/hcai/bin/allused.lst | grep -a -c -E "${srcapp}|${tgtapp}"`
		if [ $cnt -ge 1 ];
		then
			echo "skip apps used/downloaded before: $srcapp or $tgtapp ..."
			continue
		fi

		echo "downloading source app $srcapp ..."
		downloadapk.sh "$srcapp" s.apk 1> /dev/null 2>&1
		if [ ! -s s.apk ];then continue; fi
		checkapk "s.apk"
		if [ $? -ne 1 ];then
			rm s.apk
			continue
		fi

		echo "downloading target app $tgtapp ..."
		downloadapk.sh "$tgtapp" t.apk 1> /dev/null 2>&1
		if [ ! -s t.apk ];then continue; fi
		checkapk "t.apk"
		if [ $? -ne 1 ];then
			rm t.apk
			continue
		fi
		mkdir -p $pc
		mv s.apk t.apk $pc
		mv $pc $OUTDIR
		echo $srcapp"->"$tgtapp >> /home/hcai/bin/allused.lst
		echo $srcapp"->"$tgtapp >> /home/hcai/bin/newpairs.lst
		(( pc ++ ))
	done
done
exit 0

