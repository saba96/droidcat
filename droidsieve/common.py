from sklearn.multiclass import OneVsRestClassifier
from sklearn.preprocessing import label_binarize

from sklearn.metrics import precision_score,recall_score,f1_score,roc_auc_score,accuracy_score,auc,roc_curve

import matplotlib.pyplot as plt

import numpy as np
import pickle
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectFromModel

def roc_bydate(g_binary, model, trainfeatures, trainlabels, testfeatures, testlabels, datatag):
    m = model

    suffix='det' if g_binary else 'cat'
    fnTarget = '../ML/roc_curves/pickle.'+datatag+'.'+suffix

    labels=set()
    for l in trainlabels: labels.add(l)
    for l in testlabels: labels.add(l)
    labels = np.array(list(labels))
    trainlabels = label_binarize(trainlabels, classes=labels)
    testlabels = label_binarize(testlabels, classes=labels)
    n_classes = len(labels)

    if not g_binary:
        m = OneVsRestClassifier(model)
        #test_score = m.fit ( trainfeatures, trainlabels ).decision_function(testfeatures)

    test_score = m.fit ( trainfeatures, trainlabels ).predict_proba(testfeatures)

    if not g_binary:
        '''
        fpr = dict()
        tpr = dict()
        roc_auc = dict()
        for i in range(n_classes):
            fpr[i], tpr[i], _ = roc_curve(testlabels[:, i], test_score[:, i])
            roc_auc[i] = auc(fpr[i], tpr[i])
        fpr["micro"], tpr["micro"], _ = roc_curve(testlabels.ravel(), test_score.ravel())
        roc_auc["micro"] = auc(fpr["micro"], tpr["micro"])
        '''
        fpr, tpr, _ = roc_curve(testlabels.ravel(), test_score.ravel())
        roc_auc = auc(fpr, tpr)
    else:
        fpr, tpr, _ = roc_curve(testlabels, test_score[:,1])
        roc_auc = auc(fpr, tpr)

    fhTarget = file (fnTarget, 'wb')
    pickle.dump( (fpr, tpr, roc_auc), fhTarget )
    fhTarget.close()

def processingFeatures(trainfeatures, trainlabels, testfeatures, testlabels):
    features = numpy.concatenate ( (trainfeatures, testfeatures), axis=0 )
    print "before feature scaling and selection: %d samples each with %d features" % (len(features), len(features[0]))
    print features[0]

    scaled_features = StandardScaler().fit_transform( features )

    sfm = SelectFromModel(model, threshold = 'median')
    sfm.fit( trainfeatures, trainlabels )
    selected_features = sfm.transform ( scaled_features )

    print "after feature scaling and selection: %d samples each with %d features" % (len(selected_features), len(selected_features[0]))
    print selected_features[0]

    _trainfeatures = numpy.zeros( shape=(len(trainfeatures), len(selected_features[0])) )
    _testfeatures = numpy.zeros( shape=(len(testfeatures), len(selected_features[0])) )

    for k in range(0, len(trainfeatures)):
        _trainfeatures[k] = selected_features[k]

    for k in range(0, len(testfeatures)):
        _testfeatures[k] = selected_features[k+len(trainfeatures)]

    trainfeatures = _trainfeatures
    testfeatures = _testfeatures

    return trainfeatures, testfeatures

