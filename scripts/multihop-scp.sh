#!/bin/bash
src=$1
tgt=$2
#relay=${3:-"ssh5.eecs.wsu.edu"}
relay="ssh5.eecs.wsu.edu"
#scp -r -oProxyCommand="ssh  -W %h:%p ${relay}" ${src} ${tgt}
scp -r -oProxyCommand="ssh  -W %h:%p ${relay}" "$@"
