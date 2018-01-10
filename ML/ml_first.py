# Import the random forest package
from sklearn.ensemble import RandomForestClassifier 
import numpy
import random

train_data=numpy.random.random((3,5))
print "TRAINING DATA"

# Create the random forest object which will include all the parameters
# for the fit
forest = RandomForestClassifier(n_estimators = 100)

# Fit the training data to the Survived labels and create the decision trees
#forest = forest.fit(train_data[0::,1::],train_data[0::,0])
Y=[1,0,1]
forest = forest.fit(train_data[0::,0::], Y)

print "PREDICTION INPUT"
test_data=numpy.random.random((30,5))
print test_data

# Take the same decision trees and run it on the test data
output = forest.predict(test_data)
print "PREDICTION RESULTS"
print output
print "PREDICTION SCORE"
print forest.score(test_data, numpy.ones(len(test_data)))
