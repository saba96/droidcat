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

g_binary = False # binary or multiple-class classification
dataprefix="/home/hcai/Downloads/rd_workspace/revealdroid/"
g_names=set()

def varname(p):
    for line in inspect.getframeinfo(inspect.currentframe().f_back)[3]:
        m = re.search(r'\bvarname\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', line)
        if m:
            return m.group(1)

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

def malwareCatStat(labels):
    l2c={}
    for lab in labels:
        if lab not in l2c.keys():
            l2c[lab]=0
        l2c[lab]=l2c[lab]+1
    return l2c

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

        start_time = time.time()
        if clf_type == 's':
            clf = SVC()
        elif clf_type == 'l':
            clf = LinearSVC(C=0.01,penalty="l1",dual=False)
        elif clf_type == 'r':
            clf = LogisticRegression(max_iter=1000)

    #models = (RandomForestClassifier(n_estimators = 100, random_state=0), )#ExtraTreesClassifier(n_estimators=120), GradientBoostingClassifier(n_estimators=120), BaggingClassifier (n_estimators=120), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), MultinomialNB())
    models = (SVC(), LinearSVC(C=0.01, penalty='l1', dual=False), LogisticRegression(max_iter=1000))

    print >> fh, '\t'.join(uniqLabels)

    model2ret={}
    for model in models:
        print >> fh, 'model ' + str(model)
        ret = span_detect (model, trainfeatures, trainlabels, testfeatures, testlabels)
        model2ret[str(model)] = ret

    tlabs=('precision', 'recall', 'F1', 'accuracy')
    for i in (0,1,2,3):
        print >> fh, tlabs[i]
        cols=list()
        for model in models:
            #print 'model ' + str(model)
            col=list()
            ret = model2ret[str(model)]
            col.append(ret[i])
            cols.append(col)
        for r in range(0,len(cols[0])):
            for c in range(0,len(cols)):
                print >> fh, "%s\t" % cols[c][r],
            print >> fh

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

def loadFeatures(datatag, label):
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

    '''
    f = open(tagprefix+datatag, 'rb')
    sample_features = {}
    sample_labels = {}

    try:
        fdict = pickle.load (f)
        sample_features = fdict
    except (EOFError, pickle.UnpicklingError):
        pass

    f.close()
    '''

    print >> sys.stderr, 'loaded from %s: %d feature vectors; feature vector length: %d' % (datatag, len (sample_features), len(g_names))
    return (sample_features, sample_labels)

def getfvec(fdict):
    fvecs=dict()
    for md5 in fdict.keys():
        #print md5
        #fnames = [fname for fname in fdict[md5].keys()]
        for key in fdict[md5].keys():
            if "->" in key:
                fdict[md5][key]=0
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

if __name__=="__main__":
    if len(sys.argv)>=2:
        g_binary = sys.argv[1].lower()=='true'

    '''
    datasets = [ {"benign":["zoo-benign-2010"], "malware":["zoo-2010"]},
                  {"benign":["zoo-benign-2011"], "malware":["zoo-2011"]},
                  {"benign":["zoo-benign-2012"], "malware":["zoo-2012", "malware-2013"]},
                  {"benign":["zoo-benign-2013"], "malware":["zoo-2013", "vs-2013", "malware-drebin"]},
                  {"benign":["zoo-benign-2014", "benign-2014"], "malware":["zoo-2014", "vs-2014"]},
                  {"benign":["zoo-benign-2015"], "malware":["zoo-2015", "vs-2015"]},
                  {"benign":["zoo-benign-2016"], "malware":["zoo-2016", "vs-2016"]},
                  {"benign":["benign-2017"], "malware":["zoo-2017", "malware-2017"]} ]
    '''

    datasets = [  {"benign":["zoobenign2010"], "malware":["zoo2010"]},
                  {"benign":["zoobenign2011"], "malware":["zoo2011"]},
                  {"benign":["zoobenign2012"], "malware":["zoo2012"]},
                  {"benign":["zoobenign2013"], "malware":["vs2013"]},
                  {"benign":["zoobenign2014"], "malware":["vs2014"]},
                  {"benign":["zoobenign2015"], "malware":["vs2015"]},
                  {"benign":["zoobenign2016"], "malware":["vs2016"]},
                  {"benign":["benign2017"], "malware":["zoo2017"]} ]

    '''
    datasets = [  {"benign":["zoobenign2010"], "malware":["zoo2010"]},
                  {"benign":["zoobenign2012"], "malware":["zoo2012"]},
                  {"benign":["zoobenign2014"], "malware":["vs2014"]},
                  {"benign":["zoobenign2015"], "malware":["vs2015"]},
                  {"benign":["zoobenign2016"], "malware":["vs2016"]},
                  {"benign":["benign2017"], "malware":["zoo2017"]} ]

    datasets = [  {"benign":["zoobenign2014"], "malware":["vs2014"]},
                  {"benign":["zoobenign2015"], "malware":["vs2015"]},
                  {"benign":["benign2017"], "malware":["zoo2017"]} ]
    '''

    #bPrune = g_binary
    bPrune = True

    fh = sys.stdout
    #fh = file ('confusion_matrix_formajorfamilyonly_holdout_all.txt', 'w')

    for i in range(0, len(datasets)-1):
        # training dataset
        #(bf1, bl1) = loadMamaFeatures(datasets[i]['benign'][0], mode, "BENIGN")
        (bft, blt) = ({}, {})
        for k in range(0, len(datasets[i]['benign'])):
            (bf, bl) = loadFeatures(datasets[i]['benign'][k], "BENIGN")
            bft.update (bf)
            blt.update (bl)
        for k in range(0, len(datasets[i]['malware'])):
            (mf, ml) = loadFeatures(datasets[i]['malware'][k], "MALICIOUS")
            bft.update (mf)
            blt.update (ml)

        for j in range(i+1, len(datasets)):
            print "train on %s ... test on %s ..." % ( datasets[i], datasets[j] )

            # testing dataset
            (bfp, blp) = ({}, {})
            for k in range(0, len(datasets[j]['benign'])):
                (bf, bl) = loadFeatures(datasets[j]['benign'][k], "BENIGN")
                bfp.update (bf)
                blp.update (bl)
            for k in range(0, len(datasets[j]['malware'])):
                (mf, ml) = loadFeatures(datasets[j]['malware'][k], "MALICIOUS")
                bfp.update (mf)
                blp.update (ml)

            predict(getfvec(bft),blt, getfvec(bfp),blp, fh)

    fh.flush()
    fh.close()

    sys.exit(0)

# hcai: set ts=4 tw=120 sts=4 sw=4
