#!/bin/bash

(test $# -lt 1) && (echo "too few arguments") && exit 0
fnlist=$1
total=${2:-"500"}
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

OUTDIR=`pwd`/newbenignapps_set3
mkdir -p $OUTDIR

> /home/hcai/bin/newbenignapps_set3.txt
pc=$start
while ((pc <= total))
do
	for sln in `sort -R $fnlist | tail -n 200 | awk '{print $1}'`
	do
		echo "===== try downloading app no. $pc ====="
		#line=`echo "$sln" | cut -d' ' -f1`
		line="$sln"
		app=${line}

		# skip ones already used before
		cnt=`cat /home/hcai/bin/allusedbefore3rdbenignset.txt | grep -a -c -E "${app}"`
		if [ $cnt -ge 1 ];
		then
			echo "skip apps used/downloaded before: $app ..."
			continue
		fi

		echo "downloading app $app ..."
		downloadapk.sh "$app" s.apk 1> /dev/null 2>&1
		if [ ! -s s.apk ];then continue; fi
		checkapk "s.apk"
		if [ $? -ne 1 ];then
			rm s.apk
			continue
		fi

		mv s.apk ${pc}.apk
		mv ${pc}.apk $OUTDIR
		echo $app >> /home/hcai/bin/allusedbefore3rdbenignset.txt
		echo $app >> /home/hcai/bin/newbenignapps_set3.txt
		(( pc ++ ))
	done
done
exit 0

