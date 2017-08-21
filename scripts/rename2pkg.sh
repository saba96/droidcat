#!/bin/bash

pkg=`~/bin/getpackage.sh $1 | awk '{print $2}'`
mv $1 $pkg.apk
