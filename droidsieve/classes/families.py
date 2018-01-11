from family import Family
import sys, os, pandas, operator, copy
from sklearn.feature_extraction import DictVectorizer

class Families():
    def __init__(self):
        self.families = []
        self.conf_fam_order = []
        self.accuracy = {}
        self.error = {}
        self.total_pickle = 0
        self.total_json = 0
        self.total_behav_thres = 0
        self.TP = 0
        self.FP = 0
        self.FN = 0
        self.cpTP = 0
        self.cpFP = 0
        self.cpFN = 0
        self.prec_preCP = 0
        self.reca_preCP = 0
        self.prec_posCP = 0
        self.reca_posCP = 0
        self.accuracy_posCP = 0
        self.samples_filtered = []
        self.vectoriser = None
        self.X_test = []
        self.Y_test = {}
        self.Y_test['detection'] = []
        self.Y_test['classification'] = []
        self.X_train = []
        self.Y_train = {}
        self.Y_train['detection'] = []
        self.Y_train['classification'] = []
        self.glob_f = []
        self.MD5 = []

    def print_change_for_pvt(self, pvt, fam_thresh, ta, tp, tr):
        """ 
        Print the precision and recall improvements after CP per p-value.

        :param int pvt: p-value used for these statistics
        :param int fam_thresh: threshold for samples within a family
        :param int ta: total change in accuracy from before/after CP 
        :param int tp: total change in precision from before/after CP 
        :param int tr: total change in recall from before/after CP 

        :return ta: total change in accuracy from before/after CP 
        :return tp: total change in precision from before/after CP 
        :return tr: total change in recall from before/after CP 
        :rtype: int
        """
        print "\nP-value:", pvt
        a_change = 0
        p_change = 0 
        r_change = 0
        for f in self.families:
            s_len = len(f.samples)
            if ( s_len > fam_thresh) :
                b_cp = 1.0 - float(f.misclass_preCP)/float(s_len)
                a_cp = 1.0 - float(f.misclass_posCP)/float(s_len)
                print "  ", f.name, len(f.samples), "samples (before/after CP)"
                diff = f.prec_posCP -f.prec_preCP
                p_change += diff
                print "    Precision before: %.2f after: %.2f +(%.2f)" % (f.prec_preCP, f.prec_posCP, diff)   
                diff = f.reca_posCP -f.reca_preCP 
                r_change += diff
                print "    Recall    before: %.2f after: %.2f +(%.2f)" % (f.reca_preCP, f.reca_posCP, diff)
                diff = a_cp - b_cp
                a_change += diff
                print "    Accuracy  before: %.2f after: %.2f +(%.2f)" % (b_cp, a_cp, diff)
        
    def update_accuracy(self):
        """
        store accuracy of SVM and CP decision with CP picking the class with the
        highest p-value.
        """
        for f in self.families:
            correct_svm = [s for s in f.samples if s.pred_svm == s.cli_classification.gt]
            correct_cp = [s for s in f.samples if s.pred_cp == s.cli_classification.gt]
            f.total_samples = len(f.samples) 
            try:
                svm_acc = float(len(correct_svm))/float(f.total_samples)
                cp_acc = float(len(correct_cp))/float(f.total_samples)
            except ZeroDivisionError:
                print "Family has no samples"
                sys.exit(1)
            if 'svm' in f.accuracy:
                f.accuracy['svm'].append(svm_acc)
            else:
                f.accuracy['svm'] = [svm_acc]
            if 'cp' in f.accuracy:
                f.accuracy['cp'].append(cp_acc)
            else:
                f.accuracy['cp'] = [cp_acc]
        
    # add the family if it is not present and return the Family object
    def get(self, family_name):
        """
        return the family object from the family name
        
        :param str family_name: the family name
        :return: object corresponding to family_name
        :rtype: Family
        """
        present = [f for f in self.families if f.name == family_name]
        if not present:
            f = Family(family_name)
            self.families.append(f)
            return f
        else:
            if len(present)>1: 
                raise Exception("Multiple families match name")
            else:
                return present[0]
            
    def get_avg_cc(self, fam_thresh):
        """
        Get average credibility and confidence for right and wrong decisions for
        all families having at least a minimum number of samples.
        
        :param int fam_thresh: cut-off for number of samples.
        :return: tuple of right and wrong decisions containing cred/conf scores
        :rtype: tuple
        """
        right = {}
        wrong = {}
        for f in self.families:
            if len(f.samples) > fam_thresh:
                key = f.name + '\n[' + '{0:.2f}'.format(f.accuracy['cp'][0]) + ', ' + \
                str(f.total_samples) + ']'
                right[key] = (f.cp_correct_cred, f.cp_correct_conf)
                wrong[key] = (f.cp_incorrect_cred, f.cp_incorrect_conf)            
        right = pandas.DataFrame(right).transpose()
        wrong = pandas.DataFrame(wrong).transpose()
        right.columns = ['credibility', 'confidence']
        wrong.columns = ['credibility', 'confidence']        
        return right, wrong
    
    def set_conformity(self):
        """
        For each class, set the credibility and confidence scores for SVM and 
        CP predictions with CP picking class with highest p-value
        """
        for f in self.families:
            f.set_conformity_stats()
            
    def set_interference(self, avg_pvals):
        """
        Set the top few interfering families for a given family.
        These results are obtained after calculating p-value from conformal
        evaluation.
        
        :param list avg_pvals: list of tuples contianing class and its p-val
        """
        for i, fam_name in enumerate(self.conf_fam_order):
            fams = copy.deepcopy(self.conf_fam_order)
            del fams[i]
            avg_pvals[i] = ['%.2f' % pval for pval in avg_pvals[i]]
            pval_pairs = zip(fams, avg_pvals[i])
            pval_pairs.sort(key=operator.itemgetter(1))
            pval_pairs.reverse()
            self.interference = pval_pairs[:3]
    
    def pprint_conf_summary(self):
        """
        print accuracy for SVM and CP after running CP
        """
        for fam_name in self.conf_fam_order:
            print '\n'+ fam_name + '\n---------------'
            print 'SVM Accuracy:%.2f' % self.get(fam_name).svm_accuracy
            print 'CP Accuracy:%.2f' % self.get(fam_name).cp_accuracy
            print 'Total:%d' % self.get(fam_name).total_samples
            print self.interference
            
    def pprint_conformity(self):
        """
        print credibility and confidence score for SVM decisions for each family
        """
        for f in self.families:
            f.pprint_conformity(self.conf_fam_order)
            
    def pprint(self):
        """
        pretty print the contents of each family and each sample in the family
        """
        for f in self.families:
            print f.name + ":"
            for s in f.samples:
                print "\t" + s.md5
                
    def create_fv(self, samples, test_samples, ft, ft_max, detection):
        """
        After reading all samples, create families from samples.
        
        :param list samples: list of all samples read
        :param Families fs: A families class to hold list of families.
        """
        for f in self.families:
            f.samples = []
        for s in samples:
            #s.family = s.family.split('_', 1)[0]
            self.get(s.cli_classification.gt).add_sample(s)
            
        D = []
        
        i=0
        while i < len(self.families):
            f = self.families[i]
            if not(len(f.samples) > ft and len(f.samples) < ft_max):
                del self.families[i]
            else:
                for s in f.samples:
                    feature_dict = {}
                    for f in s.features:
                        if 'string' in f.name or 'method_tags' in f.name or 'API' in f.name:
                            continue
                        feature_dict[f.name] = f.freq
                    D.append(feature_dict)
                    self.MD5.append(s.md5)
                    self.samples_filtered.append(s)
                i+=1
        
        if detection:
            print 'Building feature vectors for detection.'
        else:
            print 'Building feature vectors for classification.'
            
        self.vectoriser = DictVectorizer(sparse=False)
        self.X_train = self.vectoriser.fit_transform(D)
        self.glob_f = self.vectoriser.feature_names_
        
        for idx, s in enumerate(self.samples_filtered):
            s.sanitize()
            s.fvec = self.X_train[idx]
            self.Y_train['detection'].append(s.cli_detection.gt)
            self.Y_train['classification'].append(s.cli_classification.gt)
    
        print 'Parsing testing samples'            
        for s in test_samples:
            feature_dict = {}
            for f in s.features:
                feature_dict[f.name] = f.freq
            s.fvec = self.vectoriser.transform(feature_dict)[0]
            self.X_test.append(s.fvec)
            self.Y_test['detection'].append(s.cli_detection.gt)
            self.Y_test['classification'].append(s.cli_classification.gt)      
        
        print '%d training samples, %d testing samples'%(len(self.X_train),len(self.X_test))
            

