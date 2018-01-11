#!/usr/bin/env python
# this module leverages androguard: http://code.google.com/p/androguard/

import sys
import subprocess
import os
import re
import xml.dom
from time import sleep
import logging, logging.config
import datetime

import CoIs
from CoIs import *



if __name__ == "__main__":
    print "what's wrong here?"
    if(len(sys.argv) < 1):
        sys.exit()
