#!/bin/bash

for zipapk in *.apk
do
    mkdir tmp
    mv $zipapk tmp/
    cd tmp/
    7z e -pinfected $zipapk
    rm *.apk
    mv * $zipapk
    mv $zipapk ../
    cd ..
    rm -rf tmp
done
exit 0

