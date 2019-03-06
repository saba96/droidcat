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

import pickle

g_binary = False # binary or multiple-class classification
tagprefix="../afonso/afonso.pickle."

def varname(p):
    for line in inspect.getframeinfo(inspect.currentframe().f_back)[3]:
        m = re.search(r'\bvarname\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', line)
        if m:
            return m.group(1)

# hold-out 20% evaluation
def span_detect(model, trainfeatures, trainlabels, testfeatures, testlabels):

    print >> sys.stdout, "%d samples for training, %d samples for testing" % (len (trainfeatures), len(testfeatures))

    model.fit ( trainfeatures, trainlabels )

    y_pred = model.predict ( testfeatures )

    if g_binary:
        prec=precision_score(testlabels, y_pred, average='binary', pos_label='MALICIOUS')
        rec=recall_score(testlabels, y_pred, average='binary', pos_label='MALICIOUS')
        f1=f1_score(testlabels, y_pred, average='binary', pos_label='MALICIOUS')
    else:
        prec=precision_score(testlabels, y_pred, average='weighted')
        rec=recall_score(testlabels, y_pred, average='weighted')
        f1=f1_score(testlabels, y_pred, average='weighted')

    acc=accuracy_score( testlabels, y_pred )

    #print "precision=%f, recall=%f, f1=%f, acc=%f" % (prec, rec, f1, acc)

    #return confusion_matrix(testlabels, predicted_labels, labels=list(uniqLabels))
    #return confusion_matrix(sublabels, predicted_labels, labels=big_families)
    return (prec, rec, f1, acc)


def selectFeatures(features, selection):
    featureSelect=[idx-1 for idx in selection]
    selectedfeatures=list()
    for featureRow in features:
        selectedfeatures.append ( featureRow[ featureSelect ] )
    return selectedfeatures

def predict(bf1, bl1, bf2, bl2, fh):

    (trainfeatures, trainlabels) = adapt (bf1, bl1)
    (testfeatures, testlabels) = adapt (bf2, bl2)

    print "======== in training dataset ======="
    l2c = malwareCatStat(trainlabels)
    for lab in l2c.keys():
        print "%s\t%s" % (lab, l2c[lab])

    print "======== in testing dataset ======="
    l2c = malwareCatStat(testlabels)
    for lab in l2c.keys():
        print "%s\t%s" % (lab, l2c[lab])

    uniqLabels = set()
    for item in testlabels:
        uniqLabels.add (item)

    #models = (RandomForestClassifier(n_estimators = 128, random_state=0), GaussianProcessClassifier(), ExtraTreesClassifier(n_estimators=120), AdaBoostClassifier(n_estimators=120), GradientBoostingClassifier(n_estimators=120), BaggingClassifier (n_estimators=120), SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())
    #models = (ExtraTreesClassifier(n_estimators=128, random_state=0),  AdaBoostClassifier(n_estimators=120), GradientBoostingClassifier(n_estimators=120), BaggingClassifier (n_estimators=120), )#SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())
    #models = (SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())

    #models = (RandomForestClassifier(n_estimators = 128, random_state=0), SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())

    models = (RandomForestClassifier(n_estimators = 120, random_state=0), ExtraTreesClassifier(n_estimators=120), )#GradientBoostingClassifier(n_estimators=120), BaggingClassifier (n_estimators=120), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), MultinomialNB())

    #fsets = (FSET_FULL,FSET_NOICC, FSET_MIN, FSET_YYY_G, FSET_FULL_TOP, FSET_YYY_TOP, FSET_FULL_TOP_G, FSET_YYY_TOP_G)
    #fsets = (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_Y, FSET_YY, FSET_YYY):

    fsets = (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_YYY, FSET_FULL_TOP, FSET_YYY_TOP, FSET_FULL_TOP_G, FSET_YYY_TOP_G)
    #fsets = (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_YYY, FSET_FULL_TOP_G, FSET_YYY_TOP_G)
    #fsets = (FSET_NOICC, FSET_G, FSET_SEC)
    #fsets = (FSET_FULL, FSET_G, FSET_SEC)
    #fsets = (FSET_FULL, )#FSET_SEC)

    #fh = file ('confusion_matrix_formajorfamilyonly_holdout_all.txt', 'w')
    print >> fh, '\t'.join(uniqLabels)

    model2ret={}
    for model in models:
        #for fset in (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_Y, FSET_YY, FSET_YYY):
        #for fset in (FSET_FULL, FSET_YYY, FSET_G):
        #for fset in (FSET_FULL,FSET_NOICC, FSET_MIN, FSET_YYY_G, FSET_FULL_TOP, FSET_YYY_TOP, FSET_FULL_TOP_G, FSET_YYY_TOP_G):
        for fset in fsets:
        #for fset in (FSET_G,):
            print >> fh, 'model ' + str(model) + "\t" + "feature set " + FSET_NAMES[str(fset)]
            #ret = span_detect(model, selectFeatures( trainfeatures, fset ), trainlabels, selectFeatures( testfeatures, fset), testlabels)
            ret = span_detect(model, trainfeatures, trainlabels, testfeatures, testlabels)
            model2ret[str(model)+str(fset)] = ret

    tlabs=('precision', 'recall', 'F1', 'accuracy')
    for i in (0,1,2,3):
        print tlabs[i]
        cols=list()
        for model in models:
            #print 'model ' + str(model)
            col=list()
            for fset in fsets:
                ret = model2ret[str(model)+str(fset)]
                col.append(ret[i])
            cols.append(col)
        for r in range(0,len(cols[0])):
            for c in range(0,len(cols)):
                print >> fh, "%s\t" % cols[c][r],
            print >> fh

def loadFeatures(datatag, label):
    f = open(tagprefix+datatag, 'rb')
    sample_features = {}
    sample_labels = {}

    try:
        fdict = pickle.load (f)
        sample_features = fdict
    except (EOFError, pickle.UnpicklingError):
        pass

    '''
    for md5 in sample_features.keys():
        sample_labels[md5] = label
    '''

    md5list=[]
    for line in file ('../ML/samplelists/md5.apks.'+datatag).readlines():
        md5list.append (line.lstrip('\r\n').rstrip('\r\n'))

    for md5 in sample_features.keys():
        if md5 not in md5list:
            del sample_features[md5]
        else:
            sample_labels[md5] = label

    f.close()

    print >> sys.stderr, 'loaded from %s: %d feature vectors' % (datatag, len (sample_features))
    return (sample_features, sample_labels)

def getfvec_org(fdict):
    fvecs=dict()
    for md5 in fdict.keys():
        #print md5
        #fnames = [fname for fname in fdict[md5].keys()]
        fvalues = [freq for freq in fdict[md5].values()]
        #print len(fnames), len(fvalues)
        fvecs[md5] = fvalues
    return fvecs

def getfvec(fdict):
    fvecs=dict()
    for md5 in fdict.keys():
        fvalues = []
        for key in fdict[md5].keys():
            if "->" not in key:
                fvalues.append( fdict[md5][key] )
        fvecs[md5] = fvalues
    return fvecs

def mergeAfonsoToDroidspan(datatag, afv, dfv):
    md5list=[]
    for line in file ('../ML/samplelists/md5.apks.'+datatag).readlines():
        md5list.append (line.lstrip('\r\n').rstrip('\r\n'))

    apklist=[]
    for line in file ('../ML/samplelists/apks.'+datatag).readlines():
        apklist.append (line.lstrip('\r\n').rstrip('\r\n'))

    # assumed entry at line no. N in one list corresponds entry at the same line in the other list
    apk2md5={}
    for i in range(0, len(apklist)):
        apk2md5 [ apklist[i] ] = md5list [i]

    ret={}
    for apk in dfv.keys():
        '''
        if apk not in apk2md5.keys():
            print "Error: %s not in the list" % (apk)
            sys.exit(0)
        '''
        assert apk in apk2md5.keys()
        '''
        if apk2md5[apk] not in afv.keys():
            print "error: %s not in %s" % (apk2md5[apk], afv.keys())
            sys.exit(0)
        '''
        dfv[apk] = dfv[apk] + afv[ apk2md5[apk] ]


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

    datasets = [  {"benign":["zoobenign2011"], "malware":["zoo2011"]},
                  {"benign":["zoobenign2015"], "malware":["vs2015"]}, ]

    '''
    datasets = [  {"benign":["zoobenign2010"], "malware":["zoo2010"]},
                  {"benign":["zoobenign2011"], "malware":["zoo2011"]},
                  {"benign":["zoobenign2013"], "malware":["vs2013"]} ]


                  {"benign":["zoobenign2011"], "malware":["zoo2011"]},
                  {"benign":["zoobenign2012"], "malware":["zoo2012"]},
                  {"benign":["zoobenign2013"], "malware":["vs2013"]},
                  {"benign":["zoobenign2014"], "malware":["vs2014"]},

                  {"benign":["zoobenign2016"], "malware":["vs2016"]},
                  {"benign":["benign2017"], "malware":["zoo2017"]} ]
    '''

    fh = sys.stdout
    #fh = file ('confusion_matrix_formajorfamilyonly_holdout_all.txt', 'w')

    for i in range(0, len(datasets)-1):
        # training dataset
        (bft, blt) = ({}, {})
        for k in range(0, len(datasets[i]['benign'])):
            (bf, bl) = loadBenignData("features_droidcat/"+datasets[i]['benign'][k])
            (abf, abl) = loadFeatures(datasets[i]['benign'][k], "BENIGN")
            mergeAfonsoToDroidspan (datasets[i]['benign'][k], getfvec(abf), bf)

            bft.update (bf)
            blt.update (bl)

        for k in range(0, len(datasets[i]['malware'])):
            (mf, ml) = loadMalwareNoFamily("features_droidcat/"+datasets[i]['malware'][k])
            (amf, aml) = loadFeatures(datasets[i]['malware'][k], "MALICIOUS")
            mergeAfonsoToDroidspan (datasets[i]['malware'][k], getfvec(amf), mf)

            bft.update (mf)
            blt.update (ml)

        for j in range(i+1, len(datasets)):
            print "train on %s ... test on %s ..." % ( datasets[i], datasets[j] )

            # testing dataset
            (bfp, blp) = ({}, {})
            for k in range(0, len(datasets[j]['benign'])):
                (bf, bl) = loadBenignData("features_droidcat/"+datasets[j]['benign'][k])
                (abf, abl) = loadFeatures(datasets[j]['benign'][k], "BENIGN")
                mergeAfonsoToDroidspan (datasets[j]['benign'][k], getfvec(abf), bf)

                bfp.update (bf)
                blp.update (bl)
            for k in range(0, len(datasets[j]['malware'])):
                (mf, ml) = loadMalwareNoFamily("features_droidcat/"+datasets[j]['malware'][k])
                (amf, aml) = loadFeatures(datasets[j]['malware'][k], "MALICIOUS")
                #print "loaded from %s: %s" % (datasets[j]['malware'], amf)
                mergeAfonsoToDroidspan (datasets[j]['malware'][k], getfvec(amf), mf)

                bfp.update (mf)
                blp.update (ml)

            predict(bft,blt, bfp,blp, fh)

    fh.flush()
    fh.close()

    sys.exit(0)

# hcai: set ts=4 tw=120 sts=4 sw=4
