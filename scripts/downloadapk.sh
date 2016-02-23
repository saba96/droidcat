#!/bin/bash
(test $# -lt 1) && exit 0
googleplay-api-master/download.py "$@"
