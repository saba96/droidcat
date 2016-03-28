#!/usr/bin/python

import virustotal
import sys
import os

# global results
g_vtresults=dict()
vt = virustotal.VirusTotal("05624ee52e1830c1a95dba137de2e2bbdb93adbb9835596af9c4656a4c4c92d0")

def scanAll(applist):
    global g_vtresults
    global vt
    tcnt=0
    fhtodo=file('./todo.lst','w')
    for app in applist:
        print "now scanning %s" % (app)
        try:
            report = vt.scan(app, reanalyze = True)
            report.join()
            assert report.done == True
            g_vtresults[app] = report # to be further examined (classification, statistics computation, etc.)

            print "results of %s (%d positives out of %d checks)" % (app, report.positives,report.total)
            fnres=app+".result"
            try:
                os.remove(fnres)
            except OSError:
                pass
            fhres=open(fnres, 'w')
            if report.positives>=1:
                tcnt+=1
            for ant,malware in report:
                if malware is not None:
                    #print "%s\t\t%s" % (ant, malware)
                    #print "%s (%s, %s):\t\t%s" % (ant[0], ant[1], ant[2], malware)
                    res="%s\t%s" % (ant[0], malware)
                    print res
                    fhres.write(res+"\n")
            print "\n"
            fhres.close()
        except Exception:
            print "scanning failed on app %s\n" % (app)
            fhtodo.write(app)
    fhtodo.close()

    return tcnt

if __name__ == "__main__":
    if len(sys.argv)<2:
        print "too few arguments to %s. please provide the directory of apps to scan" % (sys.argv[0])
        sys.exit(-1)
    dirapplist = sys.argv[1].lstrip().rstrip()
    applist=list()
    for item in os.listdir(dirapplist):
        if item.endswith(".apk"):
            applist.append(os.path.abspath(dirapplist+'/'+item))
    print "%d apps to scan..." % (len(applist))
    if len(applist)<1:
        sys.exit(0)
    tcnt = scanAll(applist)
    print "%d apps have been successfully scanned." % (tcnt)
    sys.exit(tcnt)

#/* hcai vim setting :set ts=4 tw=4 tws=4 */
