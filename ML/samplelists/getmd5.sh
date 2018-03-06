#!/bin/bash

> md5.$1
cat $1 | while read apk; do md5sum $2/$apk | awk '{print $1}' >> md5.$1; done
