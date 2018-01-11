from sample import Sample
import numpy as np
from string_analysis import floored_percentage
class Family():
    """Family class holding a list of samples"""
    def __init__(self, name):
        self.name = name
        self.total_samples = 0
        self.accuracy = {}
        self.nesize = 0
        self.fmin = -1
        self.fmax = -1
        self.pvt = -1
        self.TP = 0
        self.FN = 0
        self.FP = 0
        self.TPcp = 0
        self.FNcp = 0
        self.FPcp = 0
        self.FN_array = []
        self.prec_preCP = 0
        self.reca_preCP = 0
        self.prec_posCP = 0
        self.reca_posCP = 0
        self.svm_correct_cred = 0.0
        self.svm_correct_conf = 0.0
        self.svm_incorrect_cred = 0.0
        self.svm_incorrect_conf = 0.0
        self.cp_correct_cred = 0.0
        self.cp_correct_conf = 0.0
        self.cp_incorrect_cred = 0.0
        self.cp_incorrect_conf = 0.0 
        self.svm_cred = 0.0
        self.svm_conf = 0.0
        self.cp_cred = 0.0
        self.cp_conf = 0.0
        self.samples = []
        self.misclass_preCP = -1
        self.misclass_posCP = -1
        self.interference = []
        
    def get_sample(self, md5):
        """
        Get the sample identified by the md5 if its in the family.
        
        :param str md5: The md5 for the sample to search
        :return: sample with the specified md5
        :rtype: Sample
        """
        sample = [s for s in self.samples if s.md5 == md5]
        if sample == []: 
            raise Exception("sample not found in family")
        if len(sample)>1: 
            raise Exception("multiple samples with same md5 found")
        return sample[0]

    def print_misclassCP(self):
        """  Pirnt misclassifications for CP """
        counter=collections.Counter(self.FN_array)
        if len(self.samples) > 0:
            perc1 = 100*float(self.FN/float(len(self.samples)))
            perc1 = floored_percentage(perc1, 3)
        else:
            perc = 0
        
        print self.name, len(self.samples), "samples"
        print "\tMisclass %d times (%s)" % (self.FN, perc1)
        for key in sorted(counter.iterkeys()):
            print "\t\t-%s: %s times" % (key, counter[key])
        print
    
    def set_conformity_stats(self):
        """
        Set prediction credibility and confidence at the level of classes.
        This is done for incorrect and correct predicitons for both svm and cp.
        We let cp pick the class with the highest p-value.
        """
        svm_correct_cred = 0.0
        svm_correct_conf = 0.0
        svm_incorrect_cred = 0.0
        svm_incorrect_conf = 0.0
        cp_correct_cred = 0.0
        cp_correct_conf = 0.0
        cp_incorrect_cred = 0.0
        cp_incorrect_conf = 0.0        
        svm_correct_total = 0.0
        svm_incorrect_total = 0.0
        cp_correct_total = 0.0
        cp_incorrect_total = 0.0
        for s in self.samples:
            if s.cli_classification.gt == s.pred_svm:
                svm_correct_cred += s.svm_credibility
                svm_correct_conf += s.svm_confidence
                svm_correct_total += 1.0
            else:
                svm_incorrect_cred += s.svm_credibility
                svm_incorrect_conf += s.svm_confidence
                svm_incorrect_total += 1.0
            if s.cli_classification.gt == s.pred_cp:
                cp_correct_cred += s.cp_credibility
                cp_correct_conf += s.cp_confidence
                cp_correct_total += 1.0
            else:
                cp_incorrect_cred += s.cp_credibility
                cp_incorrect_conf += s.cp_confidence
                cp_incorrect_total += 1.0
                
        total = len(self.samples)
        if svm_correct_total > 0.0:
            self.svm_correct_cred = svm_correct_cred/svm_correct_total
        if svm_correct_total > 0.0:
            self.svm_correct_conf = svm_correct_conf/svm_correct_total
        if svm_incorrect_total > 0.0:
            self.svm_incorrect_cred = svm_incorrect_cred/svm_incorrect_total
        if svm_incorrect_total > 0.0:
            self.svm_incorrect_conf = svm_incorrect_conf/svm_incorrect_total
        if cp_correct_total > 0.0:
            self.cp_correct_cred = cp_correct_cred/cp_correct_total
        if cp_correct_total > 0.0:
            self.cp_correct_conf = cp_correct_conf/cp_correct_total
        if cp_incorrect_total > 0.0:
            self.cp_incorrect_cred = cp_incorrect_cred/cp_incorrect_total
        if cp_incorrect_total > 0.0:
            self.cp_incorrect_conf = cp_incorrect_conf/cp_incorrect_total
        self.svm_cred = (svm_correct_cred + svm_incorrect_cred)/total
        self.svm_conf = (svm_correct_conf + svm_incorrect_conf)/total
        self.cp_cred = (cp_correct_cred + cp_incorrect_cred)/total
        self.cp_conf = (cp_correct_conf + cp_incorrect_conf)/total
        print self.name, self.svm_correct_cred, self.svm_correct_conf, total
    def pprint_conformity(self, families):
        """
        Print credibilities and confidence for the svm decision for the family.
        
        :param list families: list of families in the same order as CP stores them
        """
        print self.name, ":"
        print "\tRight:(%.2f, %.2f)" \
        %(self.svm_correct_cred, self.svm_correct_conf)
        print "\tWrong: (%.2f, %.2f)" \
        %(self.svm_incorrect_cred, self.svm_incorrect_conf)

    def set_nesize(self, n):
        """ 
        Set the network traffic size.
        
        :param int n: network traffic size
        """
        self.nesize = n

    def set_pvt(self, pvt):
        """ 
        Set the current p-value.
        
        :param int pvt: current cut-off for p-values in picking prediction set
        """
        self.pvt = pvt
    
    def set_fmin(self, n):
        """ 
        Set the family feature frequency mininum (non-zero).
        
        :param int n: family feature frequency mininum
        """
        self.fmin = n

    def set_fmax(self, n):
        """ 
        Set the family feature frequency maximum (non-zero).
        
        :param int n: family feature frequency mininum
        """
        self.fmax = n

    def set_name(self, n):
        """ 
        Set the name of the Family.
        
        :param str n: name of the family
        """
        self.name = n
        
    def add_sample(self, sample):
        """ 
        Add sample that belongs to this Family. 
        
        :param Sample sample: the sample object
        """
        self.samples.append(sample)

    ## -- PRINT FEATURS STATS FOR EACH SAMPLE -- ##
    # Parent sample print based on print options
    def pprint_sample(self, print_type, j, glob_f, \
            pred, samples, s, afamily):
        """
        Prints the feature statistics for each sample.
        
        :param print_type: level of detail for printing
        :param int j: the jth sample of the family
        :param glob_f: global list of features types
        :param pred: predictions from n-fold
        :param samples: all malware samples in py
        :param s: current sample
        :param a_family: if not 'None', print stats for this family only
        """
        sample_yes = print_type == "all" or print_type == "samples"

        if sample_yes and afamily == None:
            self.print_samplef(j, pred, glob_f, samples)

        if sample_yes and afamily != None and afamily[0] == s.cli_classification.gt:
            self.print_samplef(j, pred, glob_f, samples)    

    # Prints frequency stats for one sample
    def print_samplef(self, j, pred, glob_f, samples):
        """
        Prints misclassification statistics for each sample.

        :param int j: the jth sample of the family  
        :param pred: predictions from n-fold
        :param glob_f: global list of features types
        :param samples: all malware samples in py  
        """
        print " Sample %d (of %d) %s" \
            % (j+1, len(self.samples), self.name)

        for k,s in enumerate(samples):
            if s.cli_classification.gt == self.name:
                break

        if pred[k+j] ==  samples[k+j].family:
            print " Classified correctly"
        else:
            print " Misclassified as %s" % (pred[k+j])

        data = zip(samples[k+j].fvec, glob_f)
        data = sorted(data, reverse=True)
        
        print "  Behaviors seen and how many times"
        for i in range(len(data)):
            if data[i][0] >= 1:
                smp_num = format(int(data[i][0]), '03')
                print "  %s : %s" %(smp_num, data[i][1])

        print "   Unused:" 
        for i in range(len(data)):
            if data[i][0] < 1:
                print "   %s" % (data[i][1])

    ## -- PRINT FEATURS STATS FOR EACH FAMILY -- ##
    ## Parent Family Print depending on print options
    def pprint_family(self, pt, af, k, gf, f_fmaxc, f_fminc, f_fnone):
        """
        Prints feature statistics for all families.

        :param string pt: level of detail for printing
        :param string af: if not 'None', print stats for this family only
        :param int k: the kth global feature  
        :param list gf: global features types
        :param array f_fmaxc: which feature frequency equal the max family frequency
        :param array f_fmixc: which feature frequency equal the min family frequency
        :param array f_fnone: counts the times a feature wasn't used across all family samples
        """     
        family_yes = pt == "all" or pt == "family"

        # Print All families
        if family_yes and af == None:
            if pt == "all": 
                print "\nFamily (%s) statistics:" % (self.name)
            self.print_familyf(k, gf, f_fmaxc, f_fminc, f_fnone)

        # Print one family
        if family_yes and af != None and af[0] == self.name:
            if pt == "all": 
                print "\nFamily (%s) statistics:" % (self.name)
            self.print_familyf(k, gf, f_fmaxc, f_fminc, f_fnone)

        if pt == "all" or pt == "samples" or pt == "family":
            if af == None:
                print 
            else:
                if af[0] == self.name:
                    print

    # Prints frequency stats for one family
    def print_familyf(self, k, gf, f_fmaxc, f_fminc, f_fnone):
        """
        Prints feature statistics for a family.

        :param int k: the kth global feature  
        :param list gf: global features types
        :param array f_fmaxc: which feature frequency equal the max family frequency
        :param array f_fmixc: which feature frequency equal the min family frequency
        :param array f_fnone: counts the times a feature wasn't used across all family samples
        """   
        fmean, fsum = self.familyfvecs()
        data = zip(fmean, gf, fsum)
        data = sorted(data, reverse=True) 

        for k in range(len(gf)):
            if f_fmaxc[k] > 0:
                print " Family Max (%s samples): %d %s" \
                        % (format(f_fmaxc[k], '03'), self.fmax, gf[k])
                if gf[k][:7] == "NETWORK":
                    print "\t\tAvg Network traffic", 
                    print "{:,}".format(self.nesize/len(self.samples))

        for k in range(len(gf)):
            if f_fminc[k] > 0:
                print " Family Min (%s samples): %d %s" \
                        % (format(f_fminc[k], '03'), self.fmin, gf[k])
                if gf[k][:7] == "NETWORK":
                    print "\t\tAvg Network traffic", 
                    print "{:,}".format(self.nesize/len(self.samples))

        for i in range(len(data)):
            if data[i][0] > 0: 
                print " Family average:", data[i][0], data[i][1]
                print "   This feature seen", data[i][2], "times (", 
                print float(data[i][2])/float(sum(fsum))*100, 
                print "% of family features)"

        print " Unused % across all family samples:"
        data = zip(f_fnone, gf)
        data = sorted(data, reverse=True) 
        for k in range(len(gf)):
            if f_fnone[k] > 0:
                perc0 = int(float(data[k][0])/float(len(self.samples))*100)
                print "  ", perc0, "%", data[k][1]

    ## Average arrays
    def mean(self, a):
        """ Average an array. :param array a: Array of integer values.

        :param array a: Array of integers"""
        return sum(a) / len(a)

    ## Returns family fvec mean and sum
    def familyfvecs(self):
        """ Return family feature frequency mean and sum. """
        temp = []
        for s in self.samples:
            temp.append(s.fvec)
        fmean = np.array(map(self.mean, zip(*temp)))
        fsum = [ sum(x) for x in zip(*temp) ]
        return fmean, fsum

    ## -- PRINT COMBINED FEATURS STATS FOR ALL SAMPLES -- ##
    # Also outputs csv file depending on print options
    def pprint_total(self, pt, total_fuse, glob_f, total_f, len_s, f):
        """ Prints combined feature statistics for all py samples.

        :param string pt: level of detail for printing
        :param array total_fuse: total number of times each feature was seen by a family sample
        :param list glob_f: global features types
        :param array total_f: total number of times each feature was seen in family
        :param int len_s: length of samples
        :param int f: file descriptor to write stats to if pass in -c argument
        """    
        if pt == "all" or pt == "total":
            print 
            data = zip(total_fuse, glob_f, total_f)
            data = sorted(data, reverse=True)
            print "Most/Least used Features in all", len_s, "samples"

            if f > 0:
                f.write(str(len_s)+",samples"+'\n')
                f.write("behavior,amount,,behavior,percentage\n")

            for i in range(len(data)):
                perc1 = float(data[i][0])/float(len_s)*100
                print " ", data[i][0], "samples (", perc1, "%).",
                print "This feature seen", data[i][2], "times (", 
                print float(data[i][2])/float(sum(total_f))*100, 
                print "% of features seen)"
                print "           ", data[i][1]
                if f > 0:
                    perc2 = str(float(data[i][2])/float(sum(total_f))*100)
                    f.write(str(data[i][1])+","+str(data[i][0])+",,")
                    f.write(str(data[i][1])+","+perc2+'\n')