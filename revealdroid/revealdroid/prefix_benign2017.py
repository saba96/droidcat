
import os
import string
import io
import sys

cates=[]
for cat in file('/home/hcai/bin/googleplay-api-master/cat-final.txt', 'r').readlines():
    cates.append( cat.lstrip().rstrip() )

print cates

rootdir=sys.argv[1]
for f in os.listdir(rootdir):
    if not f.endswith('txt'):
        continue
    fpath = os.path.abspath(rootdir)
    fullf = fpath + os.sep + f
    basename = os.path.basename(f)
    for cat in cates:
        if basename.startswith(cat):
            newname = basename.replace(cat, 'benign2017')
            os.system('cp ' + fullf + ' /tmp/apiusage_benign2017')
            print "will mv to " + (fpath + os.sep + newname)
            os.system('mv ' + fullf + ' ' + (fpath+os.sep+newname))
            break

sys.exit(0)
