# ----------------------------------------------------------------#
# Predictors and Comparing Probability
# ----------------------------------------------------------------#

import re
import os
import csv
import types
import math
from math import floor
from os import path
import ast
import ntpath
from sets import Set

##  Rounds up number to nearest 100
##  Unused now, might be useful for grouping
##  buffer sizes later
def roundup(x):
    """ 
    Rounding an integer. 
    :param int x: integer to be rounded
    :return: rounded integer
    :rtype: int
    """
    return int(math.ceil(x / 100.0)) * 100

def floored_percentage(val, digits):
    """
    Floor percengate number to a few digits.
    :param int val: integer to be floored
    :param int digits: number of decimal digits
    :return: floored integer
    :rtype: int
    """
    val *= 10 ** (digits )
    return '{1:.{0}f}%'.format(digits, floor(val) / 10 ** digits)

## Try to make it less troublesome to open dictionary files
def csvdir():
    """ 
    Finds path to dictionary holding file extension types.

    :return spath: path to dictionary holding extension types
    :rtype: string
    """
    xpath = os.getcwd()
    parts = xpath.split('/')
    if parts[-1] == 'mobsec-classifier':
        xpath = xpath + '/src'
    spath = xpath +'/filetype/'
    return spath

## With filename string (dir/file)
## gets file partition.
def get_exec(s):
    """
    Find the file extension type for a file.

    :param string s: filepath and filename
    :return partition: returns Android system partition 
    :rtype: string
    """
    chmodn = "'[0-7]+'"
    appfile = "^/data/data/[a-zA-Z_.-]+/files/[a-zA-Z_.-]+"
    regexp = re.compile(chmodn)
    regexp2 = re.compile(appfile)
    blob = ast.literal_eval(s['blob'])
    fl =  blob['executedFile']
    parts = fl.split('/')
    args = blob['args']

    #if len(parts) < 2: return None

    if len(parts) > 1:
        if parts[-1] == "pm":
            if args.find("'install',") > 0:
                return "silent_install"
            return None ## know installing APK

        if parts[-1] == "dexopt":
            return None ## ignore sys optimized dex files

        if parts[-1] == "cat" or parts[-1] == "sh":
            if len(args) <= 2:
                return None ## ignore 
            else:
                ## TODO: check out arguments
                argz = args.split(",")
                for a in argz:
                    if a[2:-2] == parts[-1]:
                        return None
                return None

        for p in parts:
            if p == "su":
                #len_ok = len(s['blob']['args']) > 2
                #command = s['blob']['args'].find("'-c',") > 0
                #if len_ok and command:
                if True:
                    return "su_command"
                return None ## ignore just su

            if p == "ps" or p == "logcat":
                return None # Can do much by just viewing

            if p == "chmod":
                args = s['blob']['args']
                len_ok = len(args) > 2
                if len_ok:
                    for a in args[1:-1].split(","):
                        if regexp.search(a):
                            ## TODO: add file type as well
                            #return "chmod"+str(a)[2:-1]
                            pass
                return None ## ignore plain chmod

            if p == "ln":
                # don't help
                #return "link"
                return None
            
            if p == "app_process":
                if args.find("'/system/bin',") > 0:
                    if args.find("'install',") > 0:
                        if args.find("'com.android.commands.pm.Pm',") > 0:   
                            return "silent_install"   

            if p == "mount":
                if len(args) <= 2:
                    return None ## ignore 
                else:
                    ## check out arguments
                    argz = args.split(",")
                    for a in argz:
                        pass
                    return None   

        if regexp2.search(fl):
            ## TODO: add file type as well
            #return (file type)
            pass 

        # Miss any types?
        #print s

## if extension given, label.  
## Will draw from real files later
def get_filetype(filename, extdict):
    """ 
    Groups extension types and returns overall type. 

    :param string filename: filename of the file (no directory)
    :param dictionary extdict: dictionary of extention types
    :return: extension_type
    """ 
    t = filename.split('.')
    #    or t[-1] == "tcd" \ TCD - configuration file DroidDream
    #    or t[-1] == "ico" \  icons
    #    or t[-1] == "plist" \ store serialized objects

    res = 'unknown'
    
    for key,value in extdict.d.iteritems():
        if t[-1] in value:
            res = key
            break
        
    if res=='ungrouped':
        return t[-1]
    
    if res=='openvpn' and t[-2][:9] == "onekeyvpn":
        return key

    ## Need to get real file types
    if t[-1][-7:] == "thecage" \
    or t[-1][-4:] == "ratc" \
    or t[-1][-7:] == "exploid" \
    or t[-1][-6:] == "gjsvro":
        return "exec"

    ## Prints unknown file types, add to filetype_gen.py
    #print t[-1]
    return res


##  Helps print file extension stats
"""  Implement in sample_class?  Use big dictionary
def filename_stats(fns):
    counts = {
    'dpb': 0, 'ai': 0, 'tmp' : 0, 'so' : 0, 'pkg' : 0, 'json' : 0, 'database' : 0,\
    'cfginit' : 0, 'errlog' : 0, 'text' : 0, 'app' : 0, 'web' : 0, 'cert' : 0,\
    'media' : 0, 'openvpn' : 0, 'unknown' : 0, \
    'xml': 0, 'db': 0, 'read': 0, 'exec': 0, 'dat': 0}
    
    for i in range(len(fns)):
        counts[fns[i]]+=1
        
    for key, value in counts.iteritems():
        print key+":"+ str(value)
    
    a=0
    b=0    
    for it in ['dpb', 'ai', 'tmp', 'so', 'pkg', 'json', 'database', 'cfginit']:
        a += counts[it]
    
    for it in ['errlog', 'text', 'app', 'web', 'cert', 'media', 'openvpn']:
        b+= counts[it]
        
    print "Total:", a+b+ counts['unknown']
"""

## Trying to determine useful Network behavior details 
def port_type(port):
    """ 
    Return port type given system call arguments. 
    """
    if port is 53:
        return "DNS"
    if port == 80:
        return "HTTP"
    if port >= 8000 or port == 80:
        return "server" 
    if port == 7500:
        return "TCP"
    return None
    return str(port)

def get_ip(s):
    ## 10.0.0.2.3 Android client to use IPv6 by default
    """ Return IP type given system call arguments. """
    and_client = "^\{'host': '10.0.2.3', 'retval': [0-9-]+, 'port': [0-9]+\}"
    ipv4 = "^\{'host': '[0-9.]+', 'retval': [0-9-]+, 'port': [0-9]+\}"
    ipv6mappedipv4 = "^\{'host': '::ffff:[0-9.]+', 'retval': [0-9-]+, 'port': [0-9]+\}"
    regexp = re.compile(ipv6mappedipv4)
    if regexp.search(s):
        return "ipv6_m_ipv4", s[17:].split('\'', 1)[0]
    regexp = re.compile(and_client)
    if regexp.search(s):
        return "android_client", s[10:].split('\'', 1)[0]
    regexp = re.compile(ipv4)
    if regexp.search(s):
        return "ipv4", s[10:].split('\'', 1)[0]
    #print s

def get_urltype(s):
    if s[-14:] == ".in-addr.arpa.": return "reverseDNS"
    if s[-6:] == ".co.cc":return "co_cc"
    if s[-5:] == ".mobi": return "mobi"
    if s[-5:] == ".info": return "info"
    if s[-4:] == ".net":  return "net"
    if s[-4:] == ".com":  return "com"
    if s[-4:] == ".org":  return "org"
    if s[-3:] == ".cn":   return "cn"
    if s[-3:] == ".me":   return "me"
    if s[-3:] == ".co":   return "co"

    #print s
    return s

def get_blobtype(s):
    if s[0] == "=":
        if s[1:4] == "GET":
            return "_GET"
        if s[1:5] == "POST":
            return "_POST"
    return "_other"

## Trying to determine useful Network behavior details 
def ip_type(parts1):
    if len(parts1) > 4:
        ip = parts1[4].split('\'', 1)[0]
        return ip
    if len(parts1) > 2:
        ip = parts1[1].split('\'', 2)[1]
        return ip
    print parts1

def trans_regex(ch):
    char = "[A-Za-z]"
    num = "[0-9]"
    symbol = "[_.-]"
    regexp = re.compile(char)
    if regexp.search(ch):
        return "chr"
    regexp = re.compile(num)
    if regexp.search(ch):
        return "num"
    regexp = re.compile(symbol)
    if regexp.search(ch):
        return "sym"   

def count_trans(s):
    t = 0
    prev_state = None

    for i in s:
        this_state = trans_regex(i)
        if this_state != prev_state:
            prev_state = this_state
            t = t +1

    ## Takes size of file into account
    return int(float(t)/float(len(s))*100)

def filename_regex(s):
    """ Return regular expression types for a filename. """
    allchar = "^[A-Za-z]+$"
    allnum = "^[0-9]+$"
    charsymb = "^[A-Za-z_.-]+$"
    allcns = "^[0-9A-Za-z_.-]+$"
    Lorenzo1 = "^[A-Za-z0-9]+$"
    #return str(len(s))
    regexp = re.compile(Lorenzo1)
    if regexp.search(s):
        return "charnums"

    regexp = re.compile(allchar)
    if regexp.search(s):
        return "allchar"

    regexp = re.compile(allnum)
    if regexp.search(s):
        return "allnum"

    regexp = re.compile(charsymb)
    if regexp.search(s):
        return  "charsymb"

    return "all"#+str(count_trans(s))

def get_filename(s, exdic):
    """ Given a string, return the filename. """
    try:
        parts = s.split("/")[-1]
        parts.split('.',1)[0]
        if get_filetype(parts, exdic) == "unknown":
            return parts
        if parts[0] == '.':
            return  "." + parts[1:].split(".",-1)[0]
        return parts.split(".",1)[0]
    except Exception:
        return ''

def path_leaf(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)

def get_extension(filename):

    basename = path_leaf(filename)

    if '.' in basename:
        extension = basename[basename.rfind('.')+1:]
    else:
        extension = basename
    return extension
    

## Adding network traffic sizes
def avg_nesize(s):
    """ Increases network access traffic size. """
    sz = 0
    word_counter = {}
    sza = []

    for i in range(len(s)):
        sza.append(int(s[i].split(":")[1]))
        sz = sz + int(s[i].split(":")[1])

    if len(s) == 0:
        return 0

    #Popular size
    for word in sza:
        if word in word_counter:
            word_counter[word] += 1
        else:
            word_counter[word] = 1

    popular_words = sorted(word_counter, key = word_counter.get, reverse = True)
    #return popular_words[0]

    ## Average Size
    return sz/len(s)

'''
s: a string which is a path
'''
def get_device_name(s):
    if (s.startswith('/dev/')):
        slash_index = s.find('/', 5)
        index = 0
        if slash_index == -1:
            index = len(s)
        else:
            index =slash_index
        device_name = s[5:index]
        return device_name
    else:
         return ''



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



def split_binder_method_parameter(method_name):
    parameters = re.findall("\((.+)\)", method_name)
    method_name_only = re.findall("(.+)\(", method_name)
    return method_name_only, parameters

def method_parameter_value(method_name, parameter):
    mess = re.findall(parameter+"\s=\s(.+?)\s=\s", method_name)
    if len(mess) == 0 :
        mess = re.findall(parameter+"\s=\s(.+)", method_name)
        if len(mess[0]) == 0 :
            return mess[0]
        return mess[0]
    return mess[0][0:mess[0].rfind(',')]