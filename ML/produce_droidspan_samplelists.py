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
from handle_io import io

verbose=False

def getsha256(fnapk):
    try:
        sha = subprocess.check_output(['sha256sum', fnapk])
    except Exception,e:
        print >> sys.stderr, "error occurred when executing sha256sum " + fnapk
    ret = string.split(sha.lower().lstrip().rstrip())
    if len(ret) < 2:
        print >> sys.stderr, "error in sha256sum of %s: %s" % (fnapk, sha)
        sys.exit(-1)

    return ret[0]

def getmd5(fnapk):
    return io.get_md5(fnapk)


def selectFeatures(features, selection):
    featureSelect=[idx-1 for idx in selection]
    selectedfeatures=list()
    for featureRow in features:
        selectedfeatures.append ( featureRow[ featureSelect ] )
    return selectedfeatures

if __name__=="__main__":
    if len(sys.argv)>=2:
        g_binary = sys.argv[1].lower()=='true'

    #bPrune = g_binary
    bPrune = True

    '''
    datasets = [ {"benign":["zoobenign-2010"], "malware":["zoo-2010"]},
                  {"benign":["zoobenign-2011"], "malware":["zoo-2011"]} ]

    datasets = [ {"benign":["zoobenign-2010"], "malware":["zoo-2010"]},
                  {"benign":["zoobenign-2011"], "malware":["zoo-2011"]},
                  {"benign":["zoobenign-2012"], "malware":["zoo-2012", "malware-2013"]},
                  {"benign":["zoobenign-2013"], "malware":["zoo-2013", "vs-2013", "drebin"]},
                  {"benign":["zoobenign-2014", "benign-2014"], "malware":["zoo-2014", "vs-2014"]},
                  {"benign":["zoobenign-2015"], "malware":["zoo-2015", "vs-2015"]},
                  {"benign":["zoobenign-2016"], "malware":["zoo-2016", "vs-2016"]},
                  {"benign":["benign-2017"], "malware":["zoo-2017", "malware-2017"]} ]
    datasets = [ {"benign":["zoobenign-2010"], "malware":["zoo-2010"]},
                  {"benign":["zoobenign-2011"], "malware":["zoo-2011"]},
                  {"benign":["zoobenign-2012"], "malware":["malware-2013"]},
                  {"benign":["zoobenign-2013"], "malware":["drebin"]},
                  {"benign":["zoobenign-2014", "benign-2014"], "malware":["vs-2014"]},
                  {"benign":["zoobenign-2015"], "malware":["vs-2015"]},
                  {"benign":["zoobenign-2016"], "malware":["vs-2016"]},
                  {"benign":["benign-2017"], "malware":["zoo-2017", "malware-2017"]} ]

    datasets = [ {"benign":["zoobenign-2010"], "malware":["zoo-2010"]},
                  {"benign":["zoobenign-2011"], "malware":["zoo-2011"]},
                  {"benign":["zoobenign-2012"], "malware":["zoo-2012"]},
                  {"benign":["zoobenign-2013"], "malware":["zoo-2013", "vs-2013"]},
                  {"benign":["zoobenign-2014"], "malware":["zoo-2014", "vs-2014"]},
                  {"benign":["zoobenign-2015"], "malware":["zoo-2015", "vs-2015"]},
                  {"benign":["zoobenign-2016"], "malware":["zoo-2016", "vs-2016"]},
                  {"benign":["benign-2017"], "malware":["zoo-2017"]} ]
    '''

    datasets = [ {"benign":["zoobenign-2010"], "malware":["zoo-2010"]},
                  {"benign":["zoobenign-2011"], "malware":["zoo-2011"]},
                  {"benign":["zoobenign-2012"], "malware":["zoo-2012"]},
                  {"benign":["zoobenign-2013"], "malware":["vs-2013"]},
                  {"benign":["zoobenign-2014"], "malware":["vs-2014"]},
                  {"benign":["zoobenign-2015"], "malware":["vs-2015"]},
                  {"benign":["zoobenign-2016"], "malware":["vs-2016"]},
                  {"benign":["benign-2017"], "malware":["zoo-2017"]} ]

    for i in range(0, len(datasets)):
        for k in range(0, len(datasets[i]['benign'])):
            fh = file ("samplelists/apks."+datasets[i]['benign'][k],'w')
            (bf, bl) = loadBenignData("features_droidcat/"+datasets[i]['benign'][k])
            for apk in bf.keys():
                print >> fh, apk
            fh.flush()
            fh.close()
        for k in range(0, len(datasets[i]['malware'])):
            fh = file ("samplelists/apks."+datasets[i]['malware'][k],'w')
            (mf, ml) = loadMalwareNoFamily("features_droidcat/"+datasets[i]['malware'][k])
            for apk in mf.keys():
                print >> fh, apk
            fh.flush()
            fh.close()

    sys.exit(0)

# hcai: set ts=4 tw=120 sts=4 sw=4
