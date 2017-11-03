#!/bin/bash 

for fn in *.apk; do if [ ! -s $fn ];then rm $fn; fi; done
