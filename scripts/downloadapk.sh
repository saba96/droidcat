#!/bin/bash
(test $# -lt 1) && exit 0
/home/hcai/bin/googleplay-api-master/download.py "$@"
