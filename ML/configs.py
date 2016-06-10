#!/usr/bin/python

'''
directory of all feature text files
'''
FTXT_DIR="/home/hcai/ML/features/"

'''
benign app feature text files
'''
FTXT_BENIGN_G = FTXT_DIR+"gfeatures-benign.txt"
FTXT_BENIGN_ICC = FTXT_DIR+"iccfeatures-benign.txt"
FTXT_BENIGN_SEC = FTXT_DIR+"securityfeatures-benign.txt"

'''
malware feature text files
'''
FTXT_MALWARE_G = FTXT_DIR+"gfeatures-malware.txt"
FTXT_MALWARE_ICC = FTXT_DIR+"iccfeatures-malware.txt"
FTXT_MALWARE_SEC = FTXT_DIR+"securityfeatures-malware.txt"

'''
VirusTotal malware detection results
'''
malwareResultDir="/home/hcai/testbed/cg.instrumented/malware/installed"
malwareMappingFile="/home/hcai/testbed/mapping.malware"

'''
shell script for retrieving package name of a given APK
'''
BIN_GETPACKNAME='/home/hcai/bin/getpackage.sh'

# these benign apps are found malicious by VirusTotal, will be excluded from the training data set
malbenignapps=["com.ictap.casm", "com.aob", "com.vaishnavism.vishnusahasranaamam.english", "com.hardcoreapps.loboshaker"]


'''
Feature sets
'''
FSET_FULL = range(1,123)

FSET_G = range(1,30)+range(89,123)
FSET_ICC = range(30,37)
FSET_SEC = range(37,89)

FSET_MIN = [1,2,3,10,13,16,19,35,39,41,53,55]

FSET_Y = [1,2,3,10,13,16,19,37,39,41,53,55,57,58,59,60,61,63,73,74,75,76,78,80,81,82,83,84,93,94,95,96,105,106,117,118]

FSET_YY = [1,2,3,10,13,16,19,37,39,41,53,57,58,59,60,61,63,73,74,75,76,78,80,81,82,83,84,93,94,95,96,105,106,117,118, 11,14,22,24,30,35,38,40,43,44,54,56,62,64,65,67,86,88,99,100,101,102,103,104,107,108]

FSET_YYY = [1,2,3,10,13,16,19,37,39,41,53,55,57,58,59,60,61,63,73,74,75,76,78,80,81,82,83,84,93,94,95,96,105,106,117,118, 11,14,22,24,30,35,38,40,43,44,54,56,62,64,65,67,86,88,99,100,101,102,103,104,107,108, 12,15,23,28,32,34,36,42]


# hcai: set ts=4 tw=100 sts=4 sw=4

