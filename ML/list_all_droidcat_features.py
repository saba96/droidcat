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

from configs import *
from featureLoader import *

g_binary = False # binary or multiple-class classification

HOLDOUT_RATE=0.33

def varname(p):
    for line in inspect.getframeinfo(inspect.currentframe().f_back)[3]:
        m = re.search(r'\bvarname\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', line)
        if m:
            return m.group(1)

def get_families(path_md5_families):
    families = {}
    metainfo = open(path_md5_families)
    for line in metainfo.readlines():
        split = line.split()
        if len(split) == 2:
            md5 = str(split[0]).strip()
            date = str(split[1]).strip()
            families[md5] = date
    return families


if __name__=="__main__":
    if len(sys.argv)>=2:
        g_binary = sys.argv[1].lower()=='true'

    #bPrune = g_binary
    bPrune = True

    datasets = [ {"benign":["zoobenign2010"], "malware":["zoo2010"]},
                  {"benign":["zoobenign2011"], "malware":["zoo2011"]},
                  {"benign":["zoobenign2012"], "malware":["zoo2012", "malware2013"]},
                  {"benign":["zoobenign2013"], "malware":["zoo2013", "vs2013", "malware-drebin"]},
                  {"benign":["zoobenign2014", "benign2014"], "malware":["zoo2014", "vs2014"]},
                  {"benign":["zoobenign2015"], "malware":["zoo2015", "vs2015"]},
                  {"benign":["zoobenign2016"], "malware":["zoo2016", "vs2016"]},
                  {"benign":["benign2017"], "malware":["zoo2017", "malware2017"]} ]

    fh = sys.stdout
    #fh = file ('confusion_matrix_formajorfamilyonly_holdout_all.txt', 'w')

    for i in range(0, len(datasets)):
        print "work on %s ... " % ( datasets[i] )
        (bft, blt) = ({}, {})
        for k in range(0, len(datasets[i]['benign'])):
            (bf, bl) = loadBenignData("features_droidcat/"+datasets[i]['benign'][k])
            bft.update (bf)
            blt.update (bl)

        bfh = file ('benign-%d.txt' % (2010+i), 'w')
        for key in bft.keys():
            print >> bfh, "%s,BENIGN,%s" % (key, bft[key])

        bfh.close()

        (mft, mlt) = ({}, {})
        for k in range(0, len(datasets[i]['malware'])):
            (mf, ml) = loadMalwareNoFamily("features_droidcat/"+datasets[i]['malware'][k])
            mft.update (mf)

            mfam = get_families ("../ML/md5families/"+datasets[i]['malware'][k]+".txt")
            newfam  = ml
            for a in ml.keys():
                if a in mfam.keys():
                    newfam[a] = mfam[a]
            mlt.update ( newfam )

        mfh = file ('malware-%d.txt' % (2010+i), 'w')
        for key in mft.keys():
            print >> mfh, "%s,%s,%s" % (key, mlt[key], mft[key])

        mfh.close()

    fh.flush()
    fh.close()

    sys.exit(0)

# hcai: set ts=4 tw=120 sts=4 sw=4
