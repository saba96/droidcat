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

g_binary = False # binary or multiple-class classification
featureframe = {}
g_fnames = set()

pathprefix=os.getcwd()

#sys.stdout.write('.')

def varname(p):
    for line in inspect.getframeinfo(inspect.currentframe().f_back)[3]:
        m = re.search(r'\bvarname\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', line)
        if m:
            return m.group(1)

def malwareCatStat(labels):
    l2c={}
    for lab in labels:
        if lab not in l2c.keys():
            l2c[lab]=0
        l2c[lab]=l2c[lab]+1
    return l2c

def save(bf1, bl1, bf2, bl2, fh):
    #(trainfeatures, trainlabels) = adapt (bf1, bl1)
    #(testfeatures, testlabels) = adapt (bf2, bl2)
    (trainfeatures, trainlabels) = (bf1, bl1)
    (testfeatures, testlabels) = (bf2, bl2)
    #print trainlabels
    #print testlabels

    print "======== in training dataset ======="
    l2c = malwareCatStat(trainlabels.values())
    for lab in l2c.keys():
        print "%s\t%s" % (lab, l2c[lab])

    print "======== in testing dataset ======="
    l2c = malwareCatStat(testlabels.values())
    for lab in l2c.keys():
        print "%s\t%s" % (lab, l2c[lab])

    uniqLabels = set()
    for item in testlabels:
        uniqLabels.add (item)

    for key in trainfeatures.keys():
        s='"'+key+'"'+";"
        for feature in trainfeatures[key]:
            s=s+'"'+str(feature)+'"'+";"
        if "BENIGN" == trainlabels[key]:
            #s=s+'"'+"0"+'"'+";"
            s=s+'"'+"0"+'"'
        else:
            #s=s+'"'+"1"+'"'+";"
            s=s+'"'+"1"+'"'
        # mark this sample is to be used for training
        #s=s+'"'+"0"+'"'
        print >>fh,s

    for key in testfeatures.keys():
        #print >>fh,'"'+key+'"'+";",
        s='"'+key+'"'+";"
        for feature in testfeatures[key]:
            #print >>fh,'"'+str(feature)+'"'+";",
            s=s+'"'+str(feature)+'"'+";"
        if "BENIGN" == testlabels[key]:
            #print >>fh,'"'+"0"+'"'+";",
            #s=s+'"'+"0"+'"'+";"
            s=s+'"'+"0"+'"'
        else:
            #print >>fh,'"'+"1"+'"'+";",
            #s=s+'"'+"1"+'"'+";"
            s=s+'"'+"1"+'"'
        # mark this sample is to be used for testing
        #print >>fh,'"'+"1"+'"',
        #s=s+'"'+"0"+'"'
        print >>fh,s

def _loadFeatures(datatag,label,year=None):
    global g_fnames
    dname = pathprefix+os.sep+datatag
    sample_features = {}
    sample_labels = {}
    for entry in os.listdir(dname):
        if not entry.endswith('apk.txt'):
            continue
        apkname = entry[0:entry.find('.txt')]

        fdict={}
        for line in file(dname+os.sep+entry,'r').readlines():
            line = line.lstrip('\r\n').rstrip('\r\n')
            line = line.replace('<','').replace('>','')

            if line not in fdict.keys():
                fdict[line]=0
            fdict[line] += 1

            g_fnames.add (line)

        if year:
            apkname=year+apkname
        sample_features[apkname] = fdict
        sample_labels[apkname] = label

    print >> sys.stderr, 'loaded from %s: %d feature vectors, each sample having %d features' % (datatag, len (sample_features), len(g_fnames))
    #print sorted(g_fnames)
    return sample_features,sample_labels

def _regularizeFeatures(rawfeatures):
    ret={}
    for md5 in rawfeatures.keys():
        newfdict = copy.deepcopy(featureframe)
        for fname in rawfeatures[md5].keys():
            #assert fname in newfdict.keys()
            newfdict[fname] = rawfeatures[md5][fname]
        ret[md5] = newfdict
    return ret

def _getfvec(fdict):
    fvecs=dict()
    for md5 in fdict.keys():
        #print md5
        #fnames = [fname for fname in fdict[md5].keys()]
        fvalues = [freq for freq in fdict[md5].values()]
        #print len(fnames), len(fvalues)
        fvecs[md5] = fvalues
    return fvecs

def adapt (featureDict, labelDict):
    r=0
    c=None
    for app in featureDict.keys():
        r+=1
        if c==None:
            c = len (featureDict[app])
            print "feature vector length=%d" % (c)
            continue
        if c != len (featureDict[app]):
            print "inconsistent feature vector length for app: %s --- %d" % (app, len(featureDict[app]))
        assert c == len (featureDict[app])

    features = numpy.zeros( shape=(r,c) )
    labels = list()
    k=0
    for app in featureDict.keys():
        features[k] = featureDict[app]
        labels.append (labelDict[app])
        k+=1

    return (features, labels)

def resetframe():
    global featureframe
    featureframe={}
    #print g_fnames
    for name in g_fnames:
        featureframe[name] = 0

def loadFeatures(datatag, label,year=None):
    _features, _labels  = _loadFeatures ( datatag, label )
    return (_features, _labels)

def loadSusi(datatag,label,year=None):
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
        #(bf1, bl1) = loadMamaFeatures(datasets[i]['benign'][0], mode, "BENIGN")
        g_fnames=set()
        (bft, blt) = ({}, {})
        for k in range(0, len(datasets[i]['benign'])):
            (bf, bl) = loadFeatures(datasets[i]['benign'][k], "BENIGN")
            bft.update (bf)
            blt.update (bl)
        '''
        for k in range(0, len(datasets[i]['malware'])):
            (mf, ml) = loadFeatures(datasets[i]['malware'][k], "MALICIOUS")
            bft.update (mf)
            blt.update (ml)
        '''

        cur_fnames = copy.deepcopy(g_fnames)

        for j in range(i+1, len(datasets)):
            print "will train on %s ... and will test on %s ..." % ( datasets[i], datasets[j] )

            g_fnames = copy.deepcopy(cur_fnames)

            # testing dataset
            (bfp, blp) = ({}, {})
            '''
            for k in range(0, len(datasets[j]['benign'])):
                (bf, bl) = loadFeatures(datasets[j]['benign'][k], "BENIGN")
                bfp.update (bf)
                blp.update (bl)
            '''
            for k in range(0, len(datasets[j]['malware'])):
                (mf, ml) = loadFeatures(datasets[j]['malware'][k], "MALICIOUS")
                bfp.update (mf)
                blp.update (ml)

            resetframe()

            _bft = _regularizeFeatures ( bft )
            _bfp = _regularizeFeatures ( bfp )

            fh=file('main_test_'+str(2010+i)+'-'+str(2010+j)+".csv", 'w')
            s='"name";'
            for k in range(0,len(g_fnames)-1):
                s=s+'"'+list(g_fnames)[k]+'";'
            s=s+'"'+list(g_fnames)[len(g_fnames)-1]+'";'
            s=s+'"malic"'
            print >>fh,s
            save(_getfvec(_bft),blt, _getfvec(_bfp),blp, fh)
            fh.flush()
            fh.close()

    #fh.flush()
    #fh.close()

    sys.exit(0)

# hcai: set ts=4 tw=120 sts=4 sw=4
