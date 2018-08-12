#!/usr/bin/python

'''
directory of all feature text files
'''
import os
#FTXT_DIR=os.getcwd()+"/features/benign-ext-highcov.10m/"
#FTXT_DIR=os.getcwd()+"/features/benign-ext-highcov/"
FTXT_DIR=os.getcwd()+"/features/benign-full/"

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

FTXT_MALWARE_G_NEW = os.getcwd()+"/features/newmalware/gfeatures.txt"
FTXT_MALWARE_ICC_NEW = os.getcwd()+"/features/newmalware/iccfeatures.txt"
FTXT_MALWARE_SEC_NEW = os.getcwd()+"/features/newmalware/securityfeatures.txt"

FTXT_G = "gfeatures.txt"
FTXT_ICC = "iccfeatures.txt"
FTXT_SEC = "securityfeatures.txt"
#FTXT_SEC = "securityfeatures.txt.org"


malwareFamilyListFile="malwareFamilies.txt"

'''threshold with which a family will be pruned if its size is under this value'''
PRUNE_THRESHOLD=20


#these benign apps are found malicious by VirusTotal, will be excluded from the training data set
malbenignapps=["com.ictap.casm", "com.aob", "com.vaishnavism.vishnusahasranaamam.english", "com.hardcoreapps.loboshaker"]


'''
Feature sets
'''
featureMappingFile="featureMapping.txt"
FSET_FULL = range(1,123)

FSET_G = range(1,30)+range(89,123)
FSET_ICC = range(30,37)
FSET_SEC = range(37,89)

FSET_MIN = [1,2,3,10,13,16,19,35,39,41,53,55]

FSET_Y = [1,2,3,10,13,16,19,37,39,41,53,55,57,58,59,60,61,63,73,74,75,76,78,80,81,82,83,84,93,94,95,96,105,106,117,118]

FSET_YY = [1,2,3,10,13,16,19,37,39,41,53,55,57,58,59,60,61,63,73,74,75,76,78,80,81,82,83,84,93,94,95,96,105,106,117,118, 11,14,22,24,30,35,38,40,43,44,54,56,62,64,65,67,86,88,99,100,101,102,103,104,107,108]

FSET_YYY = [1,2,3,10,13,16,19,37,39,41,53,55,57,58,59,60,61,63,73,74,75,76,78,80,81,82,83,84,93,94,95,96,105,106,117,118, 11,14,22,24,30,35,38,40,43,44,54,56,62,64,65,67,86,88,99,100,101,102,103,104,107,108, 12,15,23,28,32,34,36,42]
#FSET_YYY = [1,4,7,10,13,16,19,37,39,41,53,55,57,58,59,60,61,63,73,74,75,76,78,80,81,82,83,84,93,94,95,96,105,106,117,118, 11,14,22,24,30,35,38,40,43,44,54,56,62,64,65,67,86,88,99,100,101,102,103,104,107,108, 12,15,23,28,32,34,36,42]

# try more ...

FSET_FULL_TOP = [0, 37, 36, 88, 35, 38, 11, 14, 12, 39, 6, 89, 3, 40, 42, 13, 10, 20, 9, 22, 17, 19, 119, 16, 66, 73, 26, 90, 93, 91, 100, 65, 43, 15, 95, 101, 41, 18, 4, 64, 116, 117, 78, 23, 77, 84, 8, 87, 94, 85, 86, 67, 72, 92, 56, 121, 76, 27, 80, 21, 52, 25, 96, 118, 97, 79, 83, 53, 74, 34, 75, 29, 104, 48, 81, 31, 57, 7, 60, 120, 33, 32, 82, 112, 105, 113, 61, 58, 28, 49, 1, 68, 55, 50, 69, 24, 59, 5, 54, 109, 108, 114, 99, 98, 51, 71, 2, 30, 106, 70, 115, 45, 44, 63, 47, 102, 103, 107, 62, 110, 111, 46][0:30]

FSET_YYY_TOP = [0, 7, 42, 43, 63, 36, 8, 37, 44, 62, 3, 4, 19, 9, 68, 31, 64, 69, 45, 29, 34, 5, 53, 40, 35, 57, 51, 6, 56, 50, 52, 22, 23, 30, 18, 10, 65, 66, 12, 38, 41, 28, 46, 67, 39, 21, 16, 33, 32, 24, 13, 26, 25, 27, 20, 14, 48, 1, 15, 11, 47, 55, 54, 49, 61, 60, 2, 17, 58, 59][0:30]

FSET_FULL_TOP_G = [FSET_FULL_TOP[i] for i in range(0,len(FSET_FULL_TOP)) if FSET_FULL_TOP[i] in FSET_G]

FSET_YYY_TOP_G = [FSET_YYY_TOP[i] for i in range(0, len(FSET_YYY_TOP)) if FSET_YYY_TOP[i] in FSET_G]

FSET_YYY_G = [FSET_YYY[i] for i in range(0, len(FSET_YYY)) if FSET_YYY[i] in FSET_G]

FSET_NOICC = set(FSET_FULL)-set(FSET_ICC)

FSET_NAMES={str(FSET_FULL):"FSET_FULL", str(FSET_G):"FSET_G", str(FSET_ICC):"FSET_ICC", str(FSET_SEC):"FSET_SEC", str(FSET_MIN):"FSET_MIN", str(FSET_Y):"FSET_Y", str(FSET_YY):"FSET_YY", str(FSET_YYY):"FSET_YYY", str(FSET_FULL_TOP):"FSET_FULL_TOP", str(FSET_YYY_TOP):"FSET_YYY_TOP", str(FSET_FULL_TOP_G):"FSET_FULL_TOP_G", str(FSET_YYY_TOP_G):"FSET_YYY_TOP_G", str(FSET_YYY_G):"FSET_YYY_G", str(FSET_NOICC):"FSET_NOICC"}

# hcai: set ts=4 tw=100 sts=4 sw=4

