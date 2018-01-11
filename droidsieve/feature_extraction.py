#!/usr/bin/python
import sys, os 
from timeit import default_timer
import pickle
import zipfile
import argparse
import threading
from threading import Thread
import multiprocessing
from multiprocessing import Process, Queue
import datetime

from classes.sample import Sample
import utils
from settings import * 
sys.path.append(automation_path)
import apk_common

def args_parse():
    """
    Function to parse command line arguments.
    """
    parser = argparse.ArgumentParser()

    # ------ Malicious/Benign 
    malicious_parser = parser.add_mutually_exclusive_group(required=True)
    malicious_parser.add_argument('-m', '--malicious', 
                    help = "Malicious dataset", action='store_true',
                    dest = 'malicious')
    malicious_parser.add_argument('-b', '--benign', 
                    help = "Benign dataset", action='store_false',
                    dest = 'malicious')

    # ------ Dataset
    parser.add_argument('-d', '--dataset_tag', nargs = '+', metavar = 'dataset_tag', 
                    help = "Tag of the dataset containing meta_info", 
                    required = True, dest = 'dataset_tag')

    return parser.parse_args()

'''
Read md5, family name, firstseen, and path from the meta information file
'''
def read_metainfo(meta_info_file, black_list = []):
    metainfo_family = {}
    metainfo_path = {}
    metainfo_firstseen = {}
    f = open(meta_info_file, 'rb')
    while 1:
        try:
            meta = pickle.load(f)
            md5 = meta[0]
            family = meta[1]
            first_seen = meta[2]
            path = meta[3]
            if not md5 in black_list:
                metainfo_family[md5] = family
                metainfo_firstseen[md5] = first_seen
                metainfo_path[md5] = path
        except (EOFError, pickle.UnpicklingError):
            break
    f.close()
    return metainfo_family, metainfo_firstseen, metainfo_path

'''
Get sample paths for all MD5s
'''
def get_paths(paths):
    import csv
    with open(md5_path) as f:
        reader = csv.reader(f, delimiter="\t")
        d = list(reader)
    paths = dict(d)
    return paths

'''
Preprocess all apps and extract relevant features
'''
def preprocess_apks(paths):
	for sample in paths:
		extract(paths[sample])



# a detection margin of 7 minutes
def get_timezone(total_seconds, minute_margin = 7):

    timezones = { 
    -39600 : "UTC - 11 (Midway Island, Samoa)",
    -36000 : "UTC - 10 (Hawaii)",
    -32400 : "UTC - 9 (Alaska)",
    -28800 : "UTC - 8 (Pacific Time (US & Canada), Tijuana)",
    -25200 : "UTC - 7 (Arizona, Mountain Time (US & Canada), Chihuahua, Mazatlan)",
    -21600 : "UTC - 6 (Mexico City, Monterrey, Saskatchewan, Central Time (US & Canada))",
    -18000 : "UTC - 5 (Eastern Time (US & Canada), Indiana (East), Bogota, Lima)",
    -16200 : "UTC - 4:30 (Caracas)", 
    -14400 : "UTC - 4 (Atlantic Time (Canada), La Paz, Santiago)", 
    -12600 : "UTC - 3:30 (Newfoundland)", 
    -10800 : "UTC - 3 (Baghdad, Kuwait, Nairobi, Riyadh)", 
    -7200 : "UTC - 2 (Athens, Bucharest, Cairo, Harare, Helsinki, Istanbul, Jerusalem, Kyiv, Minsk, Riga, Sofia, Tallinn, Vilnius)",
    -3600 : "UTC - 1 (Azores, Cape Verde Is.)",
    0 : "UTC Casblanca, Dublin, Lisbon, London, Monrovia",
    3600 : "UTC + 1 (Amsterdam, Belgrade, Berlin, Bratislava, Brussels, Budapest, Copenhagen, Ljubljana, Madrid, Paris, Prague, Rome, Sarajevo, Skopje, Stockholm, Vienna, Warsaw, Zagreb)",
    7200 : "UTC + 2 (Athens, Bucharest, Cairo, Harare, Helsinki, Istanbul, Jerusalem, Kyiv, Minsk, Riga, Sofia, Tallinn, Vilnius)", 
    10800 : "UTC + 3 (Baghdad, Kuwait, Nairobi, Riyadh)", 
    12600 : "UTC + 3:30 (Tehran)", 
    14400 : "UTC + 4 (Moscow, Baku, Volgograd, Muscat, Tbilisi, Yerevan)",
    16200 : "UTC + 4:30 (Kabul)",
    18000 : "UTC + 5 (Karachi, Tashkent)",
    19800 : "UTC + 5:30 (Kolkata)",
    20700 : "UTC + 5:45 (Kathmandu)", 
    21600 : "UTC + 6 (Moscow, Baku, Volgograd, Muscat, Tbilisi, Yerevan)", 
    25200 : "UTC + 7 (Novosibirsk, Bangkok, Jakarta)",
    28800 : "UTC + 8 (Krasnoyarsk, Chongqing, Hong Kong, Kuala Lumpur, Perth, Singapore, Taipei, Ulaan Bataar, Urumqi)", 
    32400 : "UTC + 9 (Irkutsk, Seoul, Tokyo)", 
    34200 : "UTC + 9:30 (Adelaide, Darwin)",
    36000 : "UTC + 10 (Yakutsk, Brisbane, Canberra, Guam, Hobart, Melbourne, Port Moresby, Sydney)", 
    39600 : "UTC + 11 (Vladivostok)", 
    43200 : "UTC + 12 (Magadan, Auckland, Fiji)" }

    try:        
        for tz_seconds in timezones.keys():                 
            if ((total_seconds > tz_seconds - (minute_margin * 60)) and (total_seconds < tz_seconds + (minute_margin * 60))):                           
                return (timezones[tz_seconds], tz_seconds)
        raise KeyError
    except:
        raise

# a 5 minute margin is considered to be accurate enough
def print_accuracy(total_seconds, reference_seconds, cert_date, sig_date, minute_margin = 5):           
    # we add or substrate the local time offset for certificate_date and signature_date to be in the same time zone
    local_cert_date = cert_date + datetime.timedelta(0, reference_seconds)
    print '\nSignature file was created {0} minutes {1} seconds {2} the certificate. {3}'.format(abs(total_seconds - reference_seconds) // 60,
        abs(total_seconds - reference_seconds) % 60, 'after' if (local_cert_date <= sig_date) else 'before', 
        'So results seem accurate.' if ((total_seconds > reference_seconds - (minute_margin * 60)) and (total_seconds < reference_seconds + (minute_margin * 60))) else 'So results may not be accurate.')                  

# a 5 minute margin is considered to be accurate enough
def calculate_accuracy(total_seconds, reference_seconds, cert_date, sig_date, minute_margin = 5):           
    # we add or substrate the local time offset for certificate_date and signature_date to be in the same time zone
    return ((total_seconds > reference_seconds - (minute_margin * 60)) and (total_seconds < reference_seconds + (minute_margin * 60)))


#def extract_cert_features(sample_path):
def extract_cert_features(sample_path):
    cert_json = {}

    signature_date_highest = None
    certificate_date_smallest = None

    #signature_date, certificate_date, certificate_subject = GtmCheck.calculate_difference(sample_path)
    certificate_subject_C, certificate_subject_CN, certificate_subject_O, certificate_dates, signature_dates, cert_antagonist, len_certificates_names = apk_common.extract_certificate_features(sample_path)

    cert_json['cert_subject_c'] = certificate_subject_C
    cert_json['cert_subject_cn'] = certificate_subject_CN
    cert_json['cert_subject_o'] = certificate_subject_O
    if cert_antagonist: 
        cert_json['cert_not_valid'] = 1

    if len(signature_dates) >= 1 and len(certificate_dates) >= 1:

        signature_date_highest = signature_dates[0]
        for signature_date in signature_dates: 
            if signature_date_highest < signature_date:
                signature_date_highest = signature_date

        certificate_date_smallest = certificate_dates[0]
        for certificate_date in certificate_dates: 
            if certificate_date_smallest < certificate_date:
                certificate_date_smallest = certificate_date

	if signature_date_highest and certificate_date_smallest:
		DIF = signature_date_highest - certificate_date_smallest
		if (DIF.days == 0 or DIF.days == -1):
			try:
				TIMEZONE, REF_SECONDS = get_timezone(DIF.seconds if (DIF.days == 0) else DIF.seconds - 86400)
				accurate = calculate_accuracy(DIF.seconds if (DIF.days == 0) else DIF.seconds - 86400, REF_SECONDS, certificate_date, signature_date)	
				if accurate:
					cert_json['cert_adhoc'] = 1
				cert_json['cert_timezone'] = TIMEZONE
			except:
				pass

		cert_json['cert_diff'] = DIF.days
		cert_json['cert_date'] = certificate_date_smallest
	else: 
		print sample_path, 'Not valid GmtCheck difference'	

	return cert_json

'''
Preprocess an app and extract relevant features
'''
def preprocess_apk(md5, sample_path):
    if DEBUG: print 'Extracting', sample_path
    try:
        cert_json = extract_cert_features(sample_path)
    except Exception, e:
        print 'Error extracting features CERT in', md5, 'due to', str(e)
        import traceback
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback.print_tb(exc_traceback)
        cert_json = {'cert_antagonist': 1}

    start = default_timer()
    try:
        static_json = apk_common.extract_static_features(sample_path)
    except zipfile.BadZipfile:
        print 'WARNING BadZipfile in', md5, sample_path
        static_json = {'static_antagonist': 1}
    except Exception, e:
        print 'Error extracting features APK in', md5, ':', sample_path, 'due to', str(e)
        if not 'BadZipfile' in str(e):
            import traceback
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_tb(exc_traceback)

        static_json = {'static_antagonist': 1}

    #print '=----=', cert_json
    #print '=++++=', static_json

    if static_json and cert_json:
        static_json.update(cert_json)
    elif cert_json:
        static_json = cert_json

    return md5, default_timer() - start, static_json

def build_features(static_json, fam, md5, malicious, dataset_tag):

    sample = Sample(fam, md5, malicious)
    sample.dataset_tag.append(dataset_tag)

    entry_points_under = 0 # underaproximation of the entry points

    hls = static_json

    if 'permissions' in hls:
        permissions = hls['permissions']
        for p in permissions:
            sample.add_feature(p)

    feature = 'used_permissions'
    if feature in hls:
        permissions = hls[feature]
        for p in permissions:
            sample.add_feature_freq(feature + '.' + p, permissions[p])

    if 'incognito.permissions' in hls:
        permissions = hls['permissions']
        for p in permissions:
            sample.add_feature(p)

    feature = 'incognito.used_permissions'
    if feature in hls:
        permissions = hls[feature]
        for p in permissions:
            sample.add_feature_freq(feature + '.' + p, permissions[p])

    feature = 'incognito.sensitive_API'
    if feature in hls:
        for sapi in hls[feature]:
            sample.add_feature_freq(feature + '.' + sapi, hls[feature][sapi])

    feature = 'incognito.method_tags'
    if feature in hls:
        for f in  hls[feature]:
            sample.add_feature_freq(feature + '.' + f, hls[feature][f])

    feature = "incognito.intent_actions"
    if feature in hls:
        for action in hls[feature]:
            sample.add_feature(feature + '.' + action)
            
    feature = "incognito.intent_consts"
    if feature in hls:
        sample.add_feature_freq('num_' + feature, len(hls[feature]))

    feature = 'antagonist'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'cert_antagonist'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'static_antagonist'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'ascii_obfuscation'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'reflection'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'native_code'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'dynamic_code'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'num_permissions'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'num_third_part_permissions'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'num_libraries'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'num_activities'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])
        entry_points_under += int(hls[feature])

    feature = 'num_services'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])
        entry_points_under += int(hls[feature])

    feature = 'num_receivers'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])
        entry_points_under += int(hls[feature])

    feature = 'num_providers'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'num_files'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'intent_actions'
    if feature in hls:
        for action in hls[feature]:
            sample.add_feature(feature + '.' + action)

    feature = 'intent_objects'
    if feature in hls:
        sample.add_feature_freq('num_' + feature, len(hls[feature]))

    feature = 'intent_consts'
    if feature in hls:
        sample.add_feature_freq('num_' + feature, len(hls[feature]))

    feature = 'num_intent_actions'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'num_intent_action_android_intent'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'num_intent_action_com_android_vending'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'num_intent_action_android_net'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'num_intent_action_com_android'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'num_intent_action_other'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'num_intent_const_android_intent'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'num_intent_const_com_android_vending'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'num_intent_const_android_net'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'num_intent_const_com_android'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'num_intent_const_other'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'file' 
    if feature in hls:
        for f in  hls[feature]:
            sample.add_feature_freq(feature + '.' + f, hls[feature][f])

    feature = 'method_tags' 
    if feature in hls:
        for f in  hls[feature]:
            sample.add_feature_freq(feature + '.' + f, hls[feature][f])

    feature_package = 'package' 
    if feature_package in hls:
        sample.add_feature_freq(feature_package + '.' + 'package_subpckg', hls[feature_package].count('.')+1)
        sample.add_feature_freq(feature_package + '.' + 'package_length', len(hls[feature_package]))
        sample.add_feature_freq(feature_package + '.' + 'package_entropy', utils.shannonEntropy(hls[feature_package]))

        feature_main = 'main_activity' 
        if feature_main in hls and hls[feature_main]:
            if not hls[feature_package] in hls[feature_main]:
                sample.add_feature('PackageMissmatchMainActivity')

        feature_receivers = 'receivers'
        if feature_receivers in hls:
            types_receiver = []
            for receiver in hls[feature_receivers]:
                if not hls[feature_package] in receiver:
                    sample.add_feature('PackageMissmatchReceiver')
                type_receiver = receiver[:receiver.rfind('.')]
                if type_receiver and not type_receiver in types_receiver:
                    types_receiver.append(type_receiver)
            sample.add_feature_freq('types_receiver', len(types_receiver))

        feature_services = 'services'
        if feature_services in hls:
            types_service = []
            for service in hls[feature_services]:
                if not hls[feature_package] in service:
                    sample.add_feature('PackageMissmatchService')
                type_s = service[:service.rfind('.')]
                if type_s and not type_s in types_service:
                    types_service.append(type_s)
            sample.add_feature_freq('types_service', len(types_service))      

        feature_intent = 'intent_actions'
        if feature_intent in hls:
            for intent in hls[feature_intent]:
                if not hls[feature_package] in hls[feature_intent] and not 'android.intent.action' in intent and not 'com.android.vending' in intent  and not 'android.net' in intent  and not 'com.android' in intent:
                    sample.add_feature('PackageMissmatchIntentActions')

        feature_intent = 'intent_objects'
        if feature_intent in hls:
            for intent in hls[feature_intent]:
                if not hls[feature_package] in hls[feature_intent] and not 'android.intent.action' in intent and not 'com.android.vending' in intent  and not 'android.net' in intent  and not 'com.android' in intent:
                    sample.add_feature('PackageMissmatchIntentObjects')

        feature_intent = 'intent_consts'  
        if feature_intent in hls:
            for intent in hls[feature_intent]:
                if not hls[feature_package] in hls[feature_intent] and not 'android.intent.action' in intent and not 'com.android.vending' in intent  and not 'android.net' in intent  and not 'com.android' in intent:
                    sample.add_feature('PackageMissmatchIntentConsts')
        
    feature = 'CoIs' 
    if feature in hls:
        for f in  hls[feature]:
            sample.add_feature_freq(feature + '.' + f, hls[feature][f])

    feature = 'version_code'
    if feature in hls:
    	sample.add_feature(feature + '.' + hls[feature])

    feature = 'target_sdk'
    if feature in hls:
    	sample.add_feature(feature + '.' + hls[feature])

    feature = 'is_valid_APK'
    if feature in hls:
    	if not hls[feature]:
    		sample.add_feature('not_valid_APK')

    feature = 'su'
    if feature in hls:
    	sample.add_feature_freq('string_' + feature, hls[feature])

    feature = 'emulator'
    if feature in hls:
    	sample.add_feature_freq('string_' + feature, hls[feature])

    feature = 'sdk'
    if feature in hls:
    	sample.add_feature_freq('string_' + feature, hls[feature])

    feature = 'cert_adhoc'
    if feature in hls:
    	sample.add_feature_freq(feature, hls[feature])

    feature = 'cert_not_valid'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'cert_timezone'
    if feature in hls:
    	sample.add_feature(feature + '.' + str(hls[feature]))

    #feature = 'cert_date'
    #if feature in hls:
    #	sample.add_feature(feature + '.' + str(hls[feature].date()))

    feature = 'cert_diff'
    if feature in hls:
    	sample.add_feature(feature + '.' + str(int(hls[feature]/30)))

    feature = 'cert_subject_c'
    if feature in hls:
        length = 0
        for f in hls[feature]:
            length += len(f)
        sample.add_feature(feature + '.' + str(length))

    feature = 'cert_subject_cn'
    if feature in hls:
        length = 0
        for f in hls[feature]:
            length += len(f)
        sample.add_feature(feature + '.' + str(length))

    feature = 'cert_subject_o'
    if feature in hls:
        length = 0
        for f in hls[feature]:
            length += len(f)
        sample.add_feature(feature + '.' + str(length))

    feature = 'sensitive_API'
    if feature in hls:
        for sapi in hls[feature]:
            sample.add_feature_freq(feature + '.' + sapi, hls[feature][sapi])

    # underaproximation of the entry points
    feature = 'entry_points_under'
    sample.add_feature_freq(feature, entry_points_under)

    feature = 'native_code'
    if feature in hls and hls[feature] > 0:
        if 'file' in hls and not 'ELF' in hls['file']:
            sample.add_feature('NativeCodeWithoutElf')

    feature = 'dynamic_code'
    if feature in hls and hls[feature] > 0:
        if not 'DEX' in hls['file']:
            hls['file']['DEX'] = 0
        if not 'APK' in hls['file']:
            hls['file']['APK'] = 0
        if 'file' in hls and (hls['file']['DEX'] <= 1): # classes.dex should be expected
            sample.add_feature('DynamicCodeWithoutDEX_or_APK')
        if 'file' in hls and ('APK' in hls['file'] == 0):
            sample.add_feature('DynamicCodeWithoutDEX_or_APK')

    feature = 'e_shnum'
    if feature in hls:
        sample.add_feature_freq(feature, hls[feature])

    feature = 'e_ehsize'
    if feature in hls:
        sample.add_feature(feature + '.' + str(hls[feature]))

    feature = 'e_phentsize'
    if feature in hls:
        sample.add_feature(feature + '.' + str(hls[feature]))

    feature = 'e_shentsize'
    if feature in hls:
        sample.add_feature(feature + '.' + str(hls[feature]))

    feature = 'e_shstrndx'
    if feature in hls:
        sample.add_feature(feature + '.' + str(hls[feature]))

    feature = 'e_sh_flags'
    if feature in hls:
        for f in hls[feature]:
            sample.add_feature_freq(feature + '.' + f, hls[feature][f])

    feature = 'symbols_shared_libraries'
    if feature in hls:
        for f in hls[feature]:
            sample.add_feature(feature + '.' + f)

    feature = 'text_executable_commands'
    if feature in hls:
        for f in hls[feature]:
            sample.add_feature_freq(feature + '.' + f, hls[feature][f])

    return sample

def read_black_list(meta_file_path):

    black_list = []
    try:
        meta_file = open(meta_file_path)
    except IOError:
        print "WARNING not found", meta_file_path
        return []

    for line in meta_file.readlines():
        split = line.split()
        if len(split) > 0:
            black_list.append(split[0].strip())
    return black_list


'''
After reading all samples, create families from samples.
'''
def create_fams(samples, fs):

    for f in fs.families:
        f.samples = []
    for s in samples:
        s.family = s.family.split('_', 1)[0]
        fs.get(s.family).add_sample(s)

if __name__ == "__main__" :

    args = args_parse()
    malicious = args.malicious

    individual_overhead = []
    samples = []

    dataset_tags = args.dataset_tag
    # ---- Get started

    black_list = read_black_list('black_list.txt')

    for dataset_tag in dataset_tags: 

        print ' ::::::::::::: ' , dataset_tag, ' ::::::::::::: '
        sample_mi += '.' + dataset_tag
        out_picke += '.' + dataset_tag


        metainfo_family, metainfo_firstseen, metainfo_path = read_metainfo(sample_mi, black_list)
        # remove:
        ######metainfo_family = {'40f3f16742cd8ac8598bf859a23ac290': 'Family1', '63c52f7ad2bf622356624999e3dd3d6b': 'Family2', '930bd275a0b2c3d35b0627a8a5bd8f60': 'F2', 'aa2ad516f2e4cb1b06f2f82de3017541': 'F3'}
        ######metainfo_path = {'40f3f16742cd8ac8598bf859a23ac290': '_test_samples/00d6e661f90663eeffc10f64441b17079ea6f819.apk', '63c52f7ad2bf622356624999e3dd3d6b': '_test_samples/f78c75dd78accb8afa62109563451c4375172507.apk', '930bd275a0b2c3d35b0627a8a5bd8f60': '_test_samples/a9b65730a22fb6b78446d9afe1374d087bbf3266.apk', 'aa2ad516f2e4cb1b06f2f82de3017541': '_test_samples/02805652a3b7e87df02fb63372946a17ebd09794.apk'}
        # ---- Pool all tasks
        print 'Creating pool with %d processes' % n_procs    
        pool = multiprocessing.Pool(n_procs) #, maxtasksperchild=100

        # ---- Run all tasks
        start = default_timer()
        results = [pool.apply_async(preprocess_apk, [sample, metainfo_path[sample]]) for sample in metainfo_path]
        pool.close()
        pool.join()

        # ---- Get terminated  
        overall_overhead = default_timer() - start
        print "Extraction: %.2f seconds" % (overall_overhead)

        # ---- Process all results
        for result in results:
            result = result.get()
            if len(result) == 3:
                md5 = result[0]
                overhead_sample = result[1]
                features_sample = result[2]
            
                if features_sample:
                    individual_overhead.append(overhead_sample)
                    
                    if malicious:
                        ground_truth = metainfo_family[md5]
                    else:
                        ground_truth = 'Goodware'

                    sample = build_features(features_sample, ground_truth, md5, malicious, dataset_tag)
                    samples.append(sample)
            else:
                print 'ERROR processing result'

        print 'individual_overhead =', individual_overhead
        print 'Samples', len(samples)

        if len(samples) > 0:
            with open(out_picke, "wb") as f:
                for s in samples:
                    pickle.dump(s, f)
            f.close()
            print 'Features extracted in:', out_picke
        else: print 'No samples to extract'

        apps_with_a_feature = {}
        for sample in samples:

            # ---------------------------------------------------- #

            feature = 'DEX'
            if sample.features.freq_fname('file.' + feature) > 1:
                try:
                    count = apps_with_a_feature['file_' + feature]
                except KeyError:
                    count = 0
                apps_with_a_feature['file_' + feature] = count + 1

            feature = 'APK'
            if sample.features.freq_fname('file.' + feature) > 0:
                try:
                    count = apps_with_a_feature['file_' + feature]
                except KeyError:
                    count = 0
                apps_with_a_feature['file_' + feature] = count + 1

            feature = 'Text'
            if sample.features.freq_fname('file.' + feature) > 0:
                try:
                    count = apps_with_a_feature['file_' + feature]
                except KeyError:
                    count = 0
                apps_with_a_feature['file_' + feature] = count + 1

            feature = 'PE32'
            if sample.features.freq_fname('file.' + feature) > 0:
                try:
                    count = apps_with_a_feature['file_' + feature]
                except KeyError:
                    count = 0
                apps_with_a_feature['file_' + feature] = count + 1

            feature = 'PE32+'
            if sample.features.freq_fname('file.' + feature) > 0:
                try:
                    count = apps_with_a_feature['file_' + feature]
                except KeyError:
                    count = 0
                apps_with_a_feature['file_' + feature] = count + 1

            feature = 'ELF'
            if sample.features.freq_fname('file.' + feature) > 0:
                try:
                    count = apps_with_a_feature['file_' + feature]
                except KeyError:
                    count = 0
                apps_with_a_feature['file_' + feature] = count + 1

            feature = 'DOS'
            if sample.features.freq_fname('file.' + feature) > 0:
                try:
                    count = apps_with_a_feature['file_' + feature]
                except KeyError:
                    count = 0
                apps_with_a_feature['file_' + feature] = count + 1

            feature = 'COM'
            if sample.features.freq_fname('file.' + feature) > 0:
                try:
                    count = apps_with_a_feature['file_' + feature]
                except KeyError:
                    count = 0
                apps_with_a_feature['file_' + feature] = count + 1

            # ---------------------------------------------------- #

            feature = 'cert_adhoc'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'is_valid_APK'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'string_sdk'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'string_emulator'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'string_su'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'CoIs.ImageFileExtensionMismatch'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'CoIs.APKFileExtensionMismatch'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'CoIs.TextScriptMatch'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'not_valid_APK'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'reflection'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'native_code'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = ''
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'dynamic_code'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'ascii_obfuscation'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'antagonist'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'cert_antagonist'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'PackageMissmatchMainActivity'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'PackageMissmatchService'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'PackageMissmatchReceiver'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'PackageMissmatchIntentActions'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'PackageMissmatchIntentObjects'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'PackageMissmatchIntentConsts'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'NativeCodeWithoutElf'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'DynamicCodeWithoutDEX_or_APK'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            # ---------------------------------------------------- #

            feature = 'android.permission.INTERNET'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'android.permission.READ_CONTACTS'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'android.permission.ACCESS_COARSE_LOCATION'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'android.permission.ACCESS_FINE_LOCATION'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'android.permission.ACCESS_LOCATION_EXTRA_COMMANDS'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            # ---------------------------------------------------- #

            feature = 'method_tags.SMS'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'method_tags.SMSMESSAGE'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'method_tags.NET'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            # ---------------------------------------------------- #

            feature = 'intent_actions.android.net.conn.CONNECTIVITY_CHANGE'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'intent_actions.android.permission.ACCESS_NETWORK_STATE'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'intent_actions.android.permission.ACCESS_COARSE_LOCATION'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1


            feature = 'intent_consts.android.intent.category.HOME'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'intent_consts.android.intent.action.CALL'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            # ---------------------------------------------------- #

            feature = 'sensitive_API.Process:killProcess'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'sensitive_API.TelephonyManager:getSimSerialNumber'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'sensitive_API.TelephonyManager:getDeviceId'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            feature = 'sensitive_API.WifiManager:getIpAddress'
            if sample.features.freq_fname(feature) > 0:
                try:
                    count = apps_with_a_feature[feature]
                except KeyError:
                    count = 0
                apps_with_a_feature[feature] = count + 1

            # ---------------------------------------------------- #

        print 'apps_with_a_feature =', apps_with_a_feature

        #fs = Families()
        #create_fams(samples, fs)


