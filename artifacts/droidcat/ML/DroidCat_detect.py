# Import the random forest package
from sklearn.ensemble import RandomForestClassifier
import numpy
import random
import os
import sys
import string

from configs import *
from featureLoader import *

def detect(features, labels, testFeatures):
    featureSelect=[idx-1 for idx in FSET_YYY]
    selectedfeatures=list()
    for featureRow in features:
        selectedfeatures.append ( featureRow[ featureSelect ] )

    forest = RandomForestClassifier(n_estimators = 100)
    forest.fit( selectedfeatures, labels )

    seltestfeatures=dict()
    for app in testFeatures.keys():
        seltestfeatures = numpy.zeros( shape=(1,len(testFeatures[app])) )
        seltestfeatures.reshape(1, -1)
        seltestfeatures[0] = testFeatures[app]

        y_pred = forest.predict( seltestfeatures[0][ featureSelect ] )
        print >> sys.stdout, "detection result for %s: %s" % (app, y_pred)

if __name__=="__main__":
    g_binary = False # binary or multiple-class classification
    dirappfv = "appfv"
    if len(sys.argv)>=2:
        #print >> sys.stderr, "missing feature vector of the app under detection"
        #sys.exit(-1)
        dirappfv = sys.argv[1]
    if len(sys.argv)>=3:
        g_binary = sys.argv[2].lower()=='true'

    (features, labels, Testfeatures, Testlabels) = getTrainingData( g_binary )

    appfeatures = getTestingData ( dirappfv+"/gfeatures.txt", dirappfv+"/iccfeatures.txt", dirappfv+"/securityfeatures.txt" )
    detect (features, labels, appfeatures)

    sys.exit(0)

# hcai: set ts=4 tw=100 sts=4 sw=4
