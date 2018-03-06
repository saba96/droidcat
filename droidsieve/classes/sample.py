# ----------------------------------------------------------------#
# Feature and Sample classes
#
# Printing Functions of Family Class:
#   Print each sample's stats:
#     pprint_sample
#     print_samplef
#
#   Print Family Stats:
#     pprint_family
#     print_familyf
#       mean
#       familyfvecs
#
#   Print all sample stats
#     pprint_total
# ----------------------------------------------------------------#

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
from bases import Features, Files, ClassIdentity

class Sample():
    def __init__(self, ground_truth_label, md5, malicious = True):
        self.md5 = md5
        self.malicious = malicious
        self.features = Features()
        self.files = Files()
        self.fvec = []
        self.svec = []
        self.activities = []
        self.pred_svm = ''
        self.pred_cp = ''
        self.svm_credibility = 0.0
        self.svm_confidence = 0.0
        self.cp_credibility = 0.0
        self.cp_confidence = 0.0
        self.probables = []
        self.pvalues = []
        self.ib = []
        self.dataset_tag = []
        self.cli_detection = ClassIdentity()
        self.cli_classification = ClassIdentity()
        if self.malicious:
            self.cli_detection.gt = 'Malware'
            self.cli_classification.gt = ground_truth_label
        else:
            self.cli_detection.gt = ground_truth_label


    def update_sample(self, sample):
        self.features += sample.features

    def sanitize(self):
        """
        Reset variables in sample object for re-running the analysis.
        """
        self.fvec = []
        self.svec = []
        self.pred_svm = ''
        self.pred_cp = ''
        self.svm_credibility = 0.0
        self.svm_confidence = 0.0
        self.cp_credibility = 0.0
        self.cp_confidence = 0.0
        self.pvalues = []

    def add_feature(self, fname):
        """ Add feature to the features list.

        :param str fname: name of the feature
        """
        self.features.add_fname(fname)

    def add_feature_object(self, f):
        """ Add feature to the features list.

        :param str fname: name of the feature
        """
        self.features.add_feature_object(f)

    def add_feature_freq(self, fname, freq):
        """
        Add a feature and set its frequency in a sample

        :param str fname: name of the feature
        :param int freq: set frequency for feature
        """
        self.features.add_fname_freq(fname, freq)

    def add_file(self, path):
        """
        Add a file created by this sample,

        :param string path: path to file
        """
        self.files.add_file(path)

    def add_ib(self, i):
        """ Add to list of similar behaviors from the same feature set.

        :param string i: Feature set name"""
        self.ib.append(i)


    def set_probables(self, probables): # low_probables )
        """ Set list of probables depending on CP and p-value.

        :param list probables: Possible classes for classification, created with CP
        """
        self.probables = probables

    def ice_b(self, glob_f):
        """ For each feature, slightly increment value for features in the same feature set.

        :param list glob_f: A global list of feature"""
        for feat in self.ib:
            for i, g in enumerate(glob_f):
                if g.split('.')[0] == feat:
                    self.fvec[i] += 0.1
                    # Low seems to improve accuracy
                    # without increasing (+/-)

    def add_size(self, lensize):
        """ Sample size of family.

        :param int lensize: number of samples in family """
        self.sizes.append(lensize)

    def add_activities(self, activity):
        """ Add an activity for each high-level behavior (File Access, Network Access ... ).

        :param Activity activity: File Access, Network Access ... """
        self.activities.append(activity)

    def pprint(self):
        """
        pretty-print information for the sample.
        """
        print self.cli_detection.gt
        if self.malicious:
            print self.cli_classification.gt
        print self.md5
        self.features.pprint()
        print self.fvec
        self.files.pprint()

    # Creates a feature frequency vector
    # For each global feature, get frequency of it in Sample
    def create_fvec(self, fs):
        """
        create a feature vector for the sample.

        :param list fs: global list of features
        """
        self.fvec = [self.features.freq_fname(f) for f in fs]

    def pprint_conformity(self, families):
        """
        pretty-print credibility/confidence for SVM decision.

        :param list families: order in which CP stores list of families
        """
        if self.malicious:
            act = self.cli_classification.gt
        else:
            act = self.cli_detection.gt

        act = self.family
        pred = self.pred_svm
        print '\n'
        print self.md5
        print act, pred, \
        '{0:.4f}'.format(self.cp_credibility), \
        '{0:.4f}'.format(self.cp_confidence)
        df = pandas.DataFrame(self.pvalues, families, columns=['pval'])
        print df.sort(columns='pval', ascending=False)
