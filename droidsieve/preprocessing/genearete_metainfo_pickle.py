import os
import pickle
import datetime
from handle_io import io
import gzip

def get_first_seen(path_md5_firstseen):
    first_seen = {}
    metainfo = open(path_md5_firstseen)
    for line in metainfo.readlines():
        split = line.split()
        if len(split) == 3:
            md5 = str(split[0]).strip()
            date = str(split[1] + ' ' + split[2]).strip()
            first_seen[md5] = date
    return first_seen

def get_families(path_md5_families):
    families = {}
    metainfo = open(path_md5_families)
    for line in metainfo.readlines():
        split = line.split()
        if len(split) == 2:
            md5 = str(split[0]).strip()
            date = str(split[1]).strip()
            families[md5] = date
    return families

def get_metainfo_dir(apk_path, first_seen, out_metainfo, families = None):

    pkl = open(out_metainfo, "wb")
    subdirectories = io.get_directories(apk_path)
    for apk_directory in subdirectories:
        path = os.path.join(apk_path, apk_directory)
        print 'Exploring', path
        for file in io.get_files_in_directory(path):#, file_extension='apk'):
            file = os.path.join(path, file)
            md5 = io.get_md5(file)
            if families is None:
                family = io.get_upper_directory_name(file)
            else:
                try:
                    family = families[md5]
                except KeyError:
                    print 'Warning', md5, 'without ground truth', file
                    continue
            try:
                time = first_seen[md5]
            except:
                print 'Warning: no firstseen for', md5
                t = datetime.time(1, 2, 3)
                d = datetime.date.today()
                time = datetime.datetime.combine(d, t)
            md5_info = (md5, family, time, file)
            if md5_info is not None:
                pickle.dump(md5_info, pkl)
    pkl.close()
    print 'Check results', out_metainfo

def get_metainfo(apk_path, first_seen, out_metainfo, unzip=False, families = None, apk_filter = False):
    md5_added = []
    pkl = open(out_metainfo, "wb")
    subdirectories = io.get_directories(apk_path)
    path = apk_path
    print 'Exploring', path
    if apk_filter:
        apks = io.get_files_in_directory(path, file_extension='apk')
    else:
        apks = io.get_files_in_directory(path)
    for apk_file in apks:
        apk_file = os.path.join(path, apk_file)
        if unzip and '.gz' in apk_file:
            try:
                tmp_name = apk_file.replace('.gz', '.apk')
                if not os.path.isfile(tmp_name):
                    inF = gzip.GzipFile(apk_file, 'rb')
                    s = inF.read()
                    inF.close()

                    apk_file = tmp_name
                    outF = file(apk_file, 'wb')
                    outF.write(s)
                    outF.close()
                else:
                    apk_file = tmp_name
            except Exception, e:
                print 'Error unziping', apk_file, str(e)
                continue

        md5 = io.get_md5(apk_file)
        if md5 in md5_added:
            print 'Warning repeated sample', md5
            continue
        if families is None:
            family = io.get_upper_directory_name(apk_file)
        else:
            try:
                family = families[md5]
            except KeyError:
                print 'Warning', md5, 'without ground truth'
                continue
        try:
            time = first_seen[md5]
        except:
            print 'Warning: no firstseen for', md5
            t = datetime.time(1, 2, 3)
            d = datetime.date.today()
            time = datetime.datetime.combine(d, t)
        md5_info = (md5, family, time, apk_file)
        if md5_info is not None:
            pickle.dump(md5_info, pkl)
            md5_added.append(md5)
    pkl.close()
    print 'Extracted #samples', len(md5_added)
    print 'Check results', out_metainfo

def main():

    #first_seen = {} #get_first_seen('')
    #get_metainfo('/media/dataset/android/VirusTotalAtKoodous/', first_seen, 'metainfo.pickle.VirusTotalAtKoodous')

    #first_seen = {} #get_first_seen('')
    #get_metainfo('/media/dataset/android/samples/McAfeeClean10K', first_seen, 'metainfo.pickle.McAfeeClean10K')

    #families = get_families('/media/dataset/android/meta_info/md5_list_drebin_fam.txt')
    #first_seen = get_first_seen('/media/dataset/android/meta_info/md5_list_drebin.firstseen.txt.all')
    #get_metainfo_dir('/media/dataset/android/samples/Drebin', first_seen, 'metainfo.pickle.drebin', families)

    first_seen = {} #get_first_seen('')
    #get_metainfo_dir('/media/dataset/android/samples/AndroidMalwareGenomeProject', first_seen, 'metainfo.pickle.mg')

    '''
    get_metainfo_dir('/home/hcai/Downloads/PraGuard/TRIVIAL_APK/Malgenome', first_seen, 'metainfo.pickle.mg')
    get_metainfo_dir('/home/hcai/bin/apks2017/', first_seen, 'metainfo.pickle.benign2017')

    get_metainfo_dir('/home/hcai/Downloads/AndroZoo/benign-2016', first_seen, 'metainfo.pickle.benign2016')
    get_metainfo_dir('/home/hcai/Downloads/AndroZoo/benign-2015', first_seen, 'metainfo.pickle.benign2015')

    families = get_families ('/home/hcai/gitrepo/droidcat/ML/md5families/malware-drebin.txt')
    get_metainfo_dir('/home/hcai/testbed/input/Drebin', first_seen, 'metainfo.pickle.drebin', families)

    families = get_families ('/home/hcai/gitrepo/droidcat/ML/md5families/malware-2013.txt')
    get_metainfo_dir('/home/hcai/testbed/uniqMalware/', first_seen, 'metainfo.pickle.malware2013', families)

    families = get_families ('/home/hcai/gitrepo/droidcat/ML/md5families/malware-2017.txt')
    get_metainfo_dir('/home/hcai/testbed/newmalwareall/', first_seen, 'metainfo.pickle.malware2017', families)

    families = get_families ('/home/hcai/gitrepo/droidcat/ML/md5families/vs-2016.txt')
    get_metainfo_dir('/home/hcai/Downloads/VirusShare/2016/', first_seen, 'metainfo.pickle.vs2016', families)
    families = get_families ('/home/hcai/gitrepo/droidcat/ML/md5families/vs-2015.txt')
    get_metainfo_dir('/home/hcai/Downloads/VirusShare/2015/', first_seen, 'metainfo.pickle.vs2015', families)
    families = get_families ('/home/hcai/gitrepo/droidcat/ML/md5families/vs-2014.txt')
    get_metainfo_dir('/home/hcai/Downloads/VirusShare/2014/', first_seen, 'metainfo.pickle.vs2014', families)

    families = get_families ('/home/hcai/gitrepo/droidcat/ML/md5families/zoo-2015.txt')
    get_metainfo_dir('/home/hcai/Downloads/AndroZoo/2015/', first_seen, 'metainfo.pickle.zoo2015', families)
    families = get_families ('/home/hcai/gitrepo/droidcat/ML/md5families/zoo-2016.txt')
    get_metainfo_dir('/home/hcai/Downloads/AndroZoo/2016/', first_seen, 'metainfo.pickle.zoo2016', families)
    families = get_families ('/home/hcai/gitrepo/droidcat/ML/md5families/zoo-2017.txt')
    get_metainfo_dir('/home/hcai/Downloads/AndroZoo/2017/', first_seen, 'metainfo.pickle.zoo2017', families)
    '''

    '''
    get_metainfo_dir('/home/hcai/Downloads/AndroZoo/benign-2014', first_seen, 'metainfo.pickle.benign2014')
    get_metainfo_dir('/home/hcai/Downloads/AndroZoo/benign-2013', first_seen, 'metainfo.pickle.benign2013')
    get_metainfo_dir('/home/hcai/Downloads/AndroZoo/benign-2012', first_seen, 'metainfo.pickle.benign2012')
    '''

    '''
    get_metainfo_dir('/home/hcai/Downloads/AndroZoo/benign-2011', first_seen, 'metainfo.pickle.benign2011')
    get_metainfo_dir('/home/hcai/Downloads/AndroZoo/benign-2010', first_seen, 'metainfo.pickle.benign2010')
    '''

    '''
    families = get_families ('/home/hcai/gitrepo/droidcat/ML/md5families/vs-2013.txt')
    get_metainfo_dir('/home/hcai/Downloads/VirusShare/2013/', first_seen, 'metainfo.pickle.vs2013', families)

    families = get_families ('/home/hcai/gitrepo/droidcat/ML/md5families/zoo-2010.txt')
    get_metainfo_dir('/home/hcai/Downloads/AndroZoo/2010/', first_seen, 'metainfo.pickle.zoo2010', families)
    '''

    #families = get_families ('/home/hcai/gitrepo/droidcat/ML/md5families/zoo2011.txt')
    #get_metainfo_dir('/home/hcai/Downloads/AndroZoo/2011/', first_seen, 'metainfo.pickle.zoo2011', families)

    '''
    families = get_families ('/home/hcai/gitrepo/droidcat/ML/md5families/zoo-2012.txt')
    get_metainfo_dir('/home/hcai/Downloads/AndroZoo/2012/', first_seen, 'metainfo.pickle.zoo2012', families)

    families = get_families ('/home/hcai/gitrepo/droidcat/ML/md5families/zoo-2013.txt')
    get_metainfo_dir('/home/hcai/Downloads/AndroZoo/2013/', first_seen, 'metainfo.pickle.zoo2013', families)

    families = get_families ('/home/hcai/gitrepo/droidcat/ML/md5families/zoo-2014.txt')
    get_metainfo_dir('/home/hcai/Downloads/AndroZoo/2014/', first_seen, 'metainfo.pickle.zoo2014', families)
    '''

    '''
    get_metainfo_dir('/home/hcai/Downloads/PraGuard/TRIVIAL+STRING_ENCRYPTION+REFLECTION+CLASS_ENCRYPTION_APK/Malgenome/', first_seen, 'metainfo.pickle.obfmg')
    '''

    get_metainfo_dir('/home/hcai/Downloads/AndroZoo/malware-2017', first_seen, 'metainfo.pickle.malware-2017-more')

    #first_seen = {} #get_first_seen('')
    #get_metainfo_dir('/media/dataset/android/samples/PRAGuard/obfuscated_samples/TRIVIAL+STRING_ENCRYPTION+REFLECTION+CLASS_ENCRYPTION_APK', first_seen, 'metainfo.pickle.prg.all')

    #first_seen = {}
    #get_metainfo('/media/dataset/android/samples/Marvin/testing_benign', first_seen, 'metainfo.pickle.marvin.testing_benign', True)
    #get_metainfo('/media/dataset/android/samples/Marvin/testing_malicious', first_seen, 'metainfo.pickle.marvin.testing_malicious', True)
    #get_metainfo('/media/dataset/android/samples/Marvin/training_benign', first_seen, 'metainfo.pickle.marvin.training_benign', True)
    #get_metainfo('/media/dataset/android/samples/Marvin/training_malicious', first_seen, 'metainfo.pickle.marvin.training_malicious', True)


if __name__ == '__main__':
    main()
