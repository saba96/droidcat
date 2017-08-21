#!/bin/bash

cat $1 | awk '{printf("%d.%s\n", ++i,$0)}'
