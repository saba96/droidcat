#!/usr/bin/env python
import os
import sys
import string
import subprocess
import random
import time
import re
import numpy
from scipy import stats

def do(fname):
	hf=file(fname,'r')
	if None==hf:
		raise Exception, "failed to open file %s\n" % fname
	alllines=hf.readlines()
	hf.close()
        pers=list()
        for i in range(0,9):
            pers.append( list() )
	for line in alllines:
		line=line.strip().strip('\n')
		pair=string.split(line,'\t')
		assert len(pair)>=10
                for i in range(0,9):
                    pers[i].append( float(pair[i+1]) )
        return pers

if __name__ == "__main__":
	pers = do(sys.argv[1])
        cats=("SDK->SDK", "SDK->3rdLib", "SDK->UserCode", "3rdLib->SDK", "3rdLib->3rdLib", "3rdLib->UserCode",\
                "UserCode->SDK", "UserCode->3rdLib", "UserCode->UserCode")
        for i in range(0,9):
            #print pers[i]
            print cats[i], numpy.mean(pers[i]), numpy.std(pers[i]), stats.sem(pers[i])
	sys.exit(0)
	
