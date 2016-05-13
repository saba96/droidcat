#!/bin/bash
(test $# -lt 1) && exit 0
/home/hcai/yaogroup/Fang_CollusionAPP/code/AppDownload/download/program/googleplay-api-master/download.py "$@"
