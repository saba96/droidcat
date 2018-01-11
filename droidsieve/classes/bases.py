import os, sys
import json
import copy
import pandas
import pprint
import subprocess
import collections
import operator, re
import numpy as np
import ast
import urllib

from sets import Set
from abc import ABCMeta, abstractmethod
from string_analysis import get_filetype, port_type
from string_analysis import filename_regex
from string_analysis import get_filename, get_ip, floored_percentage

class Activity():
    """
    Activities such as File Access, Network Access ... etc.
    """
    __metaclass__ = ABCMeta
    @abstractmethod
    def inst(self, s):
        pass
        
class FSaccess(Activity):
    """
    Class for holding File Access behaviors.
    """
    def __init__(self, file_name = '', file_type = '', \
                 regex = '', loc = '', size = 0):
        self.size = size
        self.file_type = file_type
        self.file_name = file_name
        self.file_regx = regex
        self.loc = loc
        self.d = {}
    
    def inst(self, s):
        """
        Set filename, filetype, and filename regular expression.
        """
        s = ast.literal_eval(str(s))
        self.file_name = s['filename']
#         parts1 = s.split("u'")
#         parts1 = parts1[-1].split('\\')
#         file_type = get_filetype(parts1[0], self.d)
        
        self.file_type = get_filetype(self.file_name, self.d)
        fn = get_filename(self.file_name, self.d)
        self.file_regx = filename_regex(fn)

    def add_dictionary(self, d):
        """
        Get dictionary of extension types.
        """
        self.d = d
        
    # File size, file ext, regex filename
    
class NTAccess(Activity):
    """
    Class for holding Network Access behaviors.
    """
    #port, ip, size of traffic
    def __init__(self, ip = '', port = 0, \
                 port_type = '', traffic_size = 0):
        self.ip = ip
        self.port = port
        self.traffic_size = traffic_size
        self.geoinfo_raw = None
        
    def set_size(self, size):
        """
        Set size of network traffic.
        """
        self.traffic_size = size
        
    def inst(self, s):
        """
        Get port, ip and port type.
        """
        s = ast.literal_eval(s)
        self.ip = s['host']
        self.port = s['port']
        #self.ip_type, self.ip = get_ip(s)
        #self.port = port
        self.port_type = port_type(self.port)

    def get_geo(self):
        geoinfo = {}
        if not self.geoinfo_raw: 
            geoinfo = ast.literal_eval(urllib.urlopen('http://api.hostip.info/get_json.php?ip=' + self.ip).read())
            self.geoinfo_raw = geoinfo
        return geoinfo

class Execute(Activity):
    """
    Class for holding Execute behaviors.
    """
#     def __init__(self, file_name, loc):
#         self.file_name = file_name
#         self.loc = loc
#         self.perms_changed = False
        
    def inst(self, s):
        self.loc = s

class Feature():
    """
    Class for holding feature names and frequencies
    """
    def __init__(self, fname, ffrequency = 1.0, fcategory = ''):
        self.name = fname
        self.freq = ffrequency
        self.category = fcategory
    
    def inc_freq(self):
        self.freq += 1.0
        
    def set_freq(self,freq):
        """
        Set frequency to a specific value
        
        :param int freq: frequency of the feature
        """
        self.freq = float(freq)
        
    def pprint(self):
        print '[%s:%f]'%(self.name, self.freq)
        
class Features(Set):
    """
    Set of features for a sample
    """
    def get_fname(self, fname):
        """
        Get feature by name
        
        :param fname: name of the feature
        :return: feature object corresponding to the name
        """
        for f in self:
            if f.name == fname:
                return f
        return None
    
    def add_fname(self, fname):
        f = self.get_fname(fname)
        if f is None:
            f = Feature(fname)
            self.add(f)
        else:
            f.inc_freq()
            
    def add_fname_freq(self, fname, freq):
        f = self.get_fname(fname)
        if f is None:
            f = Feature(fname)
            self.add(f)
        f.set_freq(freq)
            
    def contains_fname(self, fname):
        return self.get_fname(fname) != None
    
    def freq_fname(self, fname):
        f = self.get_fname(fname)
        if f == None:
            return 0
        else: 
            return f.freq
    
    def pprint(self):
        for f in self:
            f.pprint()

    def add_feature_object(self, feature):
        self.add(feature)

class File():
    def __init__(self, path):
        self.path = path
        self.size = os.path.getsize(path)
        self.type = self.get_type()
        self.version = 1    
        self.unlinked = False 
        self.set_v_u()

    def get_path(self):
        return self.path

    def get_type(self):
        proc = subprocess.Popen("file " + self.path, stdout=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()
        return out.split(':')[-1][1:-1]

    def set_v_u(self):
        version = re.compile("^v[0-9]+")
        parts = self.path.split('.')[-2:]
        for p in parts:
            if p.find("unlinked") >= 0:
                self.unlinked = True
            if version.search(p):
                self.version = int(p[1:])
    def pprint(self):
        print '[%s:%s]'%(self.type, self.path)
            
class Files(Set):
    def add_file(self, path):  
        f = File(path)
        self.add(f)

    def pprint(self):
        for f in self:
            f.pprint()
            
class ClassIdentity():
    def __init__(self):
        self.gt = '' 
        self.pred = ''
        self.pval = {}