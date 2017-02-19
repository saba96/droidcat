#!/bin/bash

srcdir=/home/hcai/testbed/cg.instrumented/pairs/

find $srcdir/explicit_installed $srcdir/implicit_installed/  -name "*.apk"  -exec getpackage.sh {} \; | awk '{print $2}' | sort | uniq > installed_apks.txt
