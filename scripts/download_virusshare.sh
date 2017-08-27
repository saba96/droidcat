#!/bin/bash

(test $# -lt 1) && (echo "too few arguments") && exit -1

hashlist=$1

while read line;
do
    apkname=`echo $line | awk -F", " '{print 1}'`
    sha256=`echo $line | awk -F", " '{print $2}'`
    wget --load-cookies=cookies.txt "https://virusshare.com/download.4n6?sample=$sha256" -O ${sha256}.apk

done <$hashlist

exit 0
