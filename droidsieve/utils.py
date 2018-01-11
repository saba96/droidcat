#!/usr/bin/python

import os, sys, math
from sets import Set

'''
Returns the Shannon Entropy of the input
'''
def shannonEntropy(input_string):
    
    # calculate the frequency of each symbol in the string
    inputStrList = list(input_string)
    alphabet = list(Set(inputStrList))
    freqList = []
    for symbol in alphabet:
        ctr = 0
        for sym in inputStrList:
            if sym == symbol:
                ctr += 1
        freqList.append(float(ctr) / len(inputStrList))

    # Shannon entropy
    ent = 0.0
    for freq in freqList:
        ent = ent + freq * math.log(freq, 2)
    ent = -ent
    
    return ent