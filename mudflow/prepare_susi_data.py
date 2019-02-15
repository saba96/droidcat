# Import all classification package
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, AdaBoostClassifier, BaggingClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB, MultinomialNB, BernoulliNB
from sklearn.neighbors import KNeighborsClassifier

from sklearn.metrics import precision_score,recall_score,f1_score,roc_auc_score,accuracy_score

from sklearn.metrics import confusion_matrix

#from sklearn.mixture import GaussianMixture
#from sklearn.mixture import BayesianGaussianMixture
from sklearn.gaussian_process import GaussianProcessClassifier
from sklearn.gaussian_process.kernels import RBF

import numpy
import random
import os
import sys
import string

import inspect, re

#from classes.sample import Sample
import pickle
import copy

pathprefix=os.getcwd()

def varname(p):
    for line in inspect.getframeinfo(inspect.currentframe().f_back)[3]:
        m = re.search(r'\bvarname\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', line)
        if m:
            return m.group(1)

def loadFeatures(datatag,label,year=None):
    dname = pathprefix+os.sep+datatag
    susi_data=list()

    fnsusi = dname+os.sep+"susi_src_list.txt"
    for line in file(fnsusi,'r').readlines():
        line = line.lstrip('\r\n').rstrip('\r\n')
        item = line[line.rfind(os.sep)+1:len(line)]

        if year:
            item=year+item
        susi_data.append (item)

    print >> sys.stderr, 'loaded from %s: %d susi records' % (datatag, len (susi_data))
    #print sorted(g_fnames)
    return susi_data

if __name__=="__main__":
    if len(sys.argv)>=2:
        g_binary = sys.argv[1].lower()=='true'

    datasets = [  {"benign":["zoobenign2010"], "malware":["zoo2010"]},
                  {"benign":["zoobenign2011"], "malware":["zoo2011"]},
                  {"benign":["zoobenign2012"], "malware":["zoo2012"]},
                  {"benign":["zoobenign2013"], "malware":["vs2013"]},
                  {"benign":["zoobenign2014"], "malware":["vs2014"]},
                  {"benign":["zoobenign2015"], "malware":["vs2015"]},
                  {"benign":["zoobenign2016"], "malware":["vs2016"]},
                  {"benign":["benign2017"], "malware":["zoo2017"]} ]

    #bPrune = g_binary
    bPrune = True

    fh = sys.stdout
    #fh = file ('confusion_matrix_formajorfamilyonly_holdout_all.txt', 'w')

    for i in range(0, len(datasets)-1):
        # training dataset
        susi_data_all=list()
        for k in range(0, len(datasets[i]['benign'])):
            susi_data = loadFeatures(datasets[i]['benign'][k], "BENIGN")
            susi_data_all += susi_data
        '''
        for k in range(0, len(datasets[i]['malware'])):
            susi_data = loadFeatures(datasets[i]['malware'][k], "MALICIOUS")
            susi_data_all += susi_data
        '''

        for j in range(i+1, len(datasets)):
            print "will train on %s ... and will test on %s ..." % ( datasets[i], datasets[j] )

            # testing dataset
            '''
            for k in range(0, len(datasets[j]['benign'])):
                susi_data  = loadFeatures(datasets[j]['benign'][k], "BENIGN")
                susi_data_all += susi_data
            '''
            for k in range(0, len(datasets[j]['malware'])):
                susi_data  = loadFeatures(datasets[j]['malware'][k], "MALICIOUS")
                susi_data_all += susi_data

            fh=file('susi_list_'+str(2010+i)+'-'+str(2010+j)+".csv", 'w')
            for record in susi_data_all:
                print >> fh, record
            fh.flush()
            fh.close()

    #fh.flush()
    #fh.close()

    sys.exit(0)

# hcai: set ts=4 tw=120 sts=4 sw=4
