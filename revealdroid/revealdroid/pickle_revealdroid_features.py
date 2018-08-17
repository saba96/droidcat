# Import all classification package
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, AdaBoostClassifier, BaggingClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB, MultinomialNB, BernoulliNB
from sklearn.neighbors import KNeighborsClassifier

from sklearn.metrics import precision_score,recall_score,f1_score,roc_auc_score,accuracy_score

from sklearn.metrics import confusion_matrix

#from sklearn.mixture import GaussianMixture
#from sklearn.mixture import BayesianGaussianMixture
from sklearn.gaussian_process import GaussianProcessClassifier
from sklearn.gaussian_process.kernels import RBF

from sklearn.svm import SVC
from sklearn.svm import LinearSVC
from sklearn.linear_model import LogisticRegression

import numpy
import random
import os
import sys
import string

import inspect, re
import pickle

g_binary = False # binary or multiple-class classification
dataprefix="/home/hcai/Downloads/rd_workspace/revealdroid/"
g_names=set()

def varname(p):
    for line in inspect.getframeinfo(inspect.currentframe().f_back)[3]:
        m = re.search(r'\bvarname\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', line)
        if m:
            return m.group(1)

def retrieveFeature(datatag, apk):
    basename = os.path.basename(apk)
    prefix_name, ext = os.path.splitext(basename)

    def populate_fv(fv,fnfeature):
        f = open(fnfeature,'r')
        for line in f:
            k,v = line.strip().split(',')
            fv[k] = v
        return fv

    fv = dict() # initialize feature vector when first used

    PAPI_DIR=dataprefix+'data/apiusage/'
    '''
    papi_f = None
    for f in os.listdir(PAPI_DIR):
        fnfeature=datatag+'_'+prefix_name + '_apiusage.txt'
        print "locating %s ..." % (fnfeature)
        if f.endswith(fnfeature):
            print 'Found matching papi file: {}'.format(f)
            papi_f=f
            break
    fv = populate_fv(fv,papi_f,PAPI_DIR)
    #print fv
    '''

    fnapifeature=PAPI_DIR+os.sep+datatag+'_'+prefix_name + '_apiusage.txt'
    if os.path.isfile(fnapifeature):
        print 'Found matching papi file: {}'.format(fnapifeature)
        fv = populate_fv(fv,fnapifeature)

    REF_DIR=dataprefix+'../android-reflection-analysis/data/'
    '''
    ref_f = None
    for f in os.listdir(REF_DIR):
        if f.endswith(prefix_name + '_reflect.txt'):
            print 'Found matching ref file: {}'.format(f)
            ref_f = f
            break
    fv = populate_fv(fv,ref_f,REF_DIR)
    #print fv
    '''
    fnreffeature=REF_DIR+os.sep+datatag+'_'+prefix_name + '_reflect.txt'
    if os.path.isfile(fnreffeature):
        print 'Found matching ref file: {}'.format(fnreffeature)
        fv = populate_fv(fv,fnreffeature)

    NEC_DIR='data/native_external_calls/'
    '''
    nec_f = None
    for f in os.listdir(NEC_DIR):
        if f.endswith(prefix_name + '_nec.txt'):
            print 'Found matching nec file: {}'.format(f)
            nec_f=f
            break
    fv = populate_fv(fv,nec_f,NEC_DIR)
    #print fv
    '''
    fnnecfeature=NEC_DIR+os.sep+datatag+'_'+prefix_name + '_nec.txt'
    if os.path.isfile(fnnecfeature):
        print 'Found matching nec file: {}'.format(fnnecfeature)
        fv = populate_fv(fv,fnnecfeature)

    return fv

def pickleFeatures(datatag, label):
    apks=[]
    for line in file ('/home/hcai/gitrepo/droidcat//ML/samplelists/apks.'+datatag).readlines():
        apks.append (line.lstrip('\r\n').rstrip('\r\n'))

    global g_names
    sample_features = {}
    sample_labels = {}
    for apk in apks:
        sample_features[apk] = retrieveFeature(datatag,apk)
        for name in sample_features[apk].keys():
            g_names.add (name)
        sample_labels[apk] = label

    fntarget="pickled/pickle."+datatag
    f = open(fntarget, 'wb')
    pickle.dump(sample_features,f)

    f.close()

    print >> sys.stderr, 'loaded features from %s: %d feature vectors; feature vector length: %d' % (datatag, len (sample_features), len(g_names))
    print "features pickled into %s" % (fntarget)

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

    fh = sys.stdout

    for i in range(0, len(datasets)-1):
        for k in range(0, len(datasets[i]['benign'])):
            pickleFeatures(datasets[i]['benign'][k], "BENIGN")
        for k in range(0, len(datasets[i]['malware'])):
            pickleFeatures(datasets[i]['malware'][k], "MALICIOUS")

    fh.flush()
    fh.close()

    sys.exit(0)

# hcai: set ts=4 tw=120 sts=4 sw=4
