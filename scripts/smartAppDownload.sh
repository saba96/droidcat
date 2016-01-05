#!/bin/bash
(test $# -lt 1) && (echo "too few arguments") && exit 0
fnlist=$1
total=${2:-"20"}
start=${3:-"1"}

szlimit=`expr 10 "*" 1024 "*" 1024`
checkapk()
{
	[[ $# -lt 1 ]] && return 0
	apk=$1
	sdk=$(gettargetsdk.sh "$apk")
	echo "target sdk="$sdk
	[[ sdk -lt 0x15 ]] && return 0
	size=$(stat -c%s "$apk")
	echo "size="$size
	[[ size -gt szlimit ]] && return 0 
	return 1
}

pc=$start
while ((pc <= total))
do
	for sln in `sort -R $fnlist | tail -n 100 | awk '{print $1}'`
	do
		echo "===== try downloading pair no. $pc ====="
		#line=`echo "$sln" | cut -d' ' -f1`
		line="$sln"
		srcapp=${line%%-*}
		tgtapp=${line##*>}
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
		(( pc ++ ))
	done
done
exit 0

