#!/usr/bin/env python
# this module leverages androguard: http://code.google.com/p/androguard/

import sys
import subprocess
import os
import re
import xml.dom
#from sender import EventSender
#from android_tools import *
from time import sleep
import logging, logging.config
import datetime

import CoIs
from CoIs import *

# PyDev sets PYTHONPATH, use it
try:
    for p in os.environ['PYTHONPATH'].split(':'):
        if not p in sys.path:
            sys.path.append(p)
except:
    pass

try:
    sys.path.append(os.environ['ANDROGUARD_HOME'])
except Exception as e:
    print str(e)
    print "ANDROGUARD_HOME is not set. Try export ANDROGUARD_HOME=/path/to/library"
    sys.exit(-1)

from androguard.core.bytecodes import apk, dvm
from androguard.core import androconf
from androguard.core.analysis import analysis, ganalysis

from readelf import ReadElf
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from elftools.elf.descriptions import describe_sh_flags


sh_commands = [ "/system/bin/su",
                "/system/bin/sh",
                "dalvik-cache",
                "/data/log/",
                "/data/data",
                "/data",
                "/system/app",
                "/system/xbin",
                "/system/bin/pm",
                "/system/bin/am",
                "/etc/init.d",
                "/sdcard",
                "Superuser.apk",
                "busybox",
                "chown",
                "chmod",
                "fstab",
                "getprop",
                "grep",
                "install",
                "mkpartfs",
                "mkdir",
                "mount",
                "parted",
                "reboot",
                "remount",
                "rm",
                "root",
                "setprop",
                "start",
                "toolbox",
                "tune2fs"]

elf_symbols_white_list = ["ioctl",
                        "memcpy",
                        "execl",
                        "malloc",
                        "fork"]

merge_features_white_list = ["permissions",
                            "used_permissions",
                            "native_code",
                            "dynamic_code",
                            "sensitive_API",
                            "method_tags"]

def check_apk(filename):
    return androconf.is_android(filename)

def get_apk(filename):
    return apk.APK(filename)

def get_actions_old(apk):
    return apk.get_elements("action", "android:name")

def get_actions(apk):
    actions = []
    manif = apk.get_android_manifest_xml()
    if manif:
        items = manif.getElementsByTagName('action')
        if not items:
            return []
        for item in items:
            actions.append(item.getAttributeNS('http://schemas.android.com/apk/res/android', 'name'))
    return actions

def get_permissions(apk):
    return apk.get_permissions()

def run_apk(app, log=True):
    fd = open('copperdroid.interaction.log', 'aw+')
    # actually it isn't the right syntax -> see launchapp in testcasesx
    launch_app_cmd = [adb_path, "shell", "am", "start", "-W"]
    if app.get_main_activity() != None:
        component = app.get_package()+'/'+app.get_main_activity()
        tmp = [x for x in launch_app_cmd]
        tmp.append(component)
        print >> sys.stderr, tmp
        p = subprocess.Popen(tmp, stdout=subprocess.PIPE)
        (out, err) = p.communicate()
        sleep(30) # just to give the malware some slack
        if log:
            fd.write("<log>Starting activity %s</log>\n" % component)
            fd.write("<log>\n<state>execute</state>\n")
            fd.write("\t<type>stdout</type>\n")
            fd.write("\t<data>"+str(out)+"</data>\n")
            fd.write("\t<type>stderr</type>\n")
            fd.write("\t<data>"+str(err)+"</data>\n")
            fd.write("</log>\n")

    # start non-main activities
    try:
        activities = app.get_activities()
    except:
        activities = []
    for x in activities:
        if x == app.get_main_activity():
            continue # already started
        component = app.get_package()+'/'+x
        tmp = [x for x in launch_app_cmd]
        tmp.append(component)
        print >> sys.stderr, tmp
        p = subprocess.Popen(tmp, stdout=subprocess.PIPE)
        (out, err) = p.communicate()
        sleep(5) # just to give the malware some slack
        if log:
            fd.write("<log>Starting activity %s</log>\n" % component)
            fd.write("<log>\n<state>execute</state>\n")
            fd.write("\t<type>stdout</type>\n")
            fd.write("\t<data>"+str(out)+"</data>\n")
            fd.write("\t<type>stderr</type>\n")
            fd.write("\t<data>"+str(err)+"</data>\n")
            fd.write("</log>\n")

    if len(app.get_services()) != 0: # check if it has services
        for service in app.get_services():
            if log:
                fd.write("<log><state>Starting service</state>\n")
                fd.write("<type>service</type>\n")
                fd.write("<data>%s</data>\n" % service)

            launch_service_cmd = [adb_path, "shell", "am", "startservice", "%s/%s" % (app.get_package(), service)]
            p = subprocess.Popen(launch_service_cmd, stdout=subprocess.PIPE)
            (out, err) = p.communicate()
            if log:
                fd.write("\t<type>stdout</type>\n")
                fd.write("\t<data>"+str(out)+"</data>\n")
                fd.write("\t<type>stderr</type>\n")
                fd.write("\t<data>"+str(err)+"</data>\n")
        # we lose track of failing installation but we don't care ATM
        #return 0

    if len(app.get_receivers()) != 0: # if it has no service then it must be a simple receiver, just install it
        if log:
            fd.write("<log>\n\t<type>Receiver</type>\n")
            for x in get_actions(app):
                fd.write("\t<type>Action</type>\n")
                fd.write("\t<data>"+str(x)+"</data>\n")
            fd.write("</log>")
        #return 0

    # Even if the app crashes, we make sure that at the very end we run the main activity again ;)
    if app.get_main_activity() != None:
        component = app.get_package()+'/'+app.get_main_activity()
        tmp = [x for x in launch_app_cmd]
        tmp.append(component)
        print >> sys.stderr, tmp
        p = subprocess.Popen(tmp, stdout=subprocess.PIPE)
        (out, err) = p.communicate()
        sleep(10) #
        if log:
            fd.write("<log>Starting activity %s</log>\n" % component)
            fd.write("<log>\n<state>execute</state>\n")
            fd.write("\t<type>stdout</type>\n")
            fd.write("\t<data>"+str(out)+"</data>\n")
            fd.write("\t<type>stderr</type>\n")
            fd.write("\t<data>"+str(err)+"</data>\n")
            fd.write("</log>\n")

    return 0

def check_file(filename):
    abspath = os.path.abspath(filename)
    if not os.access(abspath, os.R_OK):
        return -1
    return abspath

def install_apk(filename, log=True):
    fd = open('copperdroid.installation.log', 'aw+')
    cmd = [adb_path, "install", "-r"]
    cmd.append(filename)
    p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    (out, err) = p.communicate()
    if log:
        fd.write("<log>\n<state>install</state>\n")
        fd.write("\t<type>stdout</type>\n")
        fd.write("\t<data>"+str(out)+"</data>\n")
        fd.write("\t<type>stderr</type>\n")
        fd.write("\t<data>"+str(err)+"</data>\n")
        fd.write("</log>\n")
        fd.write("</static>\n") # Questo e` l'ultimo, chiudiamo il file.
        fd.close()
    if out.find('Success') > 0:
        return 0
    else:
        return -1


def count_dyn_code(dx) :
    paths = dx.get_tainted_packages().search_methods( "Ldalvik/system/DexClassLoader;", ".", ".")
    return len(paths)

def count_native_code(dx) :
    count = 0
    d = dx.get_vm()
    for i in d.get_methods() :
        if i.get_access_flags() & 0x100 :
            count += 1
    return count

def count_reflection_code(dx) :
    paths = dx.get_tainted_packages().search_methods( "Ljava/lang/reflect/Method;", ".", ".")
    return len(paths)

def count_crypto_code(dx) :
    paths = dx.get_tainted_packages().search_methods( "Ljavax/crypto/.", ".", ".")
    return len(paths)

def count_ascii_obfuscation(vm):
    count = 0
    for classe in vm.get_classes():
        if androconf.is_ascii_problem(classe.get_name()):
            count += 1
        for method in classe.get_methods():
            if androconf.is_ascii_problem(method.get_name()):
                count += 1
    return count



#def extract_static_features_dex(app, buff_dex):
#
#    d = dvm.DalvikVMFormat( buff_dex )
#    dvmx = analysis.VMAnalysis( d )
#    d.set_vmanalysis( dvmx )
#    return parse_static_features(app, d, dvmx)



def extract_static_features(filename, raw=False):

    app = apk.APK(filename, raw)
    d = dvm.DalvikVMFormat( app.get_dex() )
    dvmx = analysis.VMAnalysis( d )
    d.set_vmanalysis( dvmx )
    return parse_static_features(app, d, dvmx)


def get_certificates_names(app_files):
    files_name = []
    signature_expr = re.compile("^(META-INF/)(.*)(\.RSA|\.DSA|\.SF)$")
    for i in app_files:
        if signature_expr.search(i):
            files_name.append(i)
    return files_name


def extract_certificate_features(filename, raw=False):
    app = apk.APK(filename, raw)
    return get_cert_info(app)

def get_cert_info(app):

    certificate_subject_C = []
    certificate_subject_CN = []
    certificate_subject_O = []
    certificate_dates = []
    signature_dates = []
    cert_antagonist = False

    certificates_names = get_certificates_names(app.get_files())

    for cert_name in certificates_names:
        if (cert_name.endswith("DSA") or (cert_name.endswith("RSA"))):
            #signature = app.get_signature()
            success, certificate = app.get_certificate(cert_name)

            if success:
                certificate_subject = certificate.subjectC() + " " + certificate.subjectCN() + " " + certificate.subjectO() #certificate.subjectDN(), certificate.subjectE(), certificate.subjectL(), certificate.subjectOU(), certificate.subjectS()
                dateString = certificate.validFromStr()
                certificate_date = datetime.datetime.strptime(str(dateString), '%a, %d %b %Y %H:%M:%S %Z') #Sun, 06 Jan 2011 10:51:40 GMT
                certificate_subject_C.append(certificate.subjectC())
                certificate_subject_CN.append(certificate.subjectCN())
                certificate_subject_O.append(certificate.subjectO())
                certificate_dates.append(certificate_date)
            else:
                cert_antagonist = True
                print 'WARNING: Cert not valid', cert_name

        if (cert_name.endswith("SF")):
            try:
                signature_date = datetime.datetime(*app.zip.getinfo(cert_name).date_time[0:6])
            except ValueError:
                signature_date = datetime.datetime(app.zip.getinfo(cert_name).date_time[0], 1, 1)
            signature_dates.append(signature_date)

    return certificate_subject_C, certificate_subject_CN, certificate_subject_O, certificate_dates, signature_dates, cert_antagonist, len(certificates_names)



def parse_static_features(app, d, dvmx):

    coi_modules = {'ImageFileExtensionMismatch', 'APKFileExtensionMismatch', 'TextScriptMatch'} #"AdvancedCodeFound", 'ELFExecutableMatch', 'DEXFileMatch', 'APKFileMatch', "EncryptedOrCompressedMatch"
    data = {}
    file_type_key = {"Text Executable":["text", "executable"], "ELF Executable":["ELF", "executable"], "fount":["font"], "APK":["Android", "application", "package", "file"], "DEX":["Dalvik", "dex",  "file"]}
    types={}
    extensions={}
    components_of_interest=[]
    num_componenets_of_interest = {}

    # -------- Strings
    su = 0
    emulator = 0
    sdk = 0
    for string in d.get_strings():
        if 'su' == string:
            su += 1
        if 'emulator' in string.lower():
            emulator  += 1
        if 'sdk' in string.lower():
            emulator  += 1
    if su > 0:
        data['su'] = su
    if emulator > 0:
        data['emulator'] = emulator
    if sdk > 0:
        data['sdk'] = sdk

    data['package'] = app.get_package()
    data['main_activity'] = app.get_main_activity()
    try:
        data['num_activities'] = len(app.get_activities())
    except:
        data['num_activities'] = 0
    data['num_services'] = len(app.get_services())
    data['num_receivers'] = len(app.get_receivers())

    if data['num_receivers'] > 0:
        data['receivers'] = app.get_receivers()

    if data['num_services'] > 0:
        data['services'] = app.get_receivers()

    num_action_android_intent = 0
    num_action_com_android_vending = 0
    num_action_android_net = 0
    num_action_com_android = 0
    num_action_other = 0
    actions = get_actions(app)
    for action in actions:
        if 'android.intent.action' in action:
            num_action_android_intent += 1
        elif 'com.android.vending' in action:
            num_action_com_android_vending += 1
        elif 'android.net' in action:
            num_action_android_net += 1
        elif 'com.android' in action:
            num_action_com_android += 1
        else:
            num_action_other += 1

    if num_action_android_intent > 0:
        data['num_intent_action_android_intent'] = num_action_android_intent

    if num_action_com_android_vending > 0:
        data['num_intent_action_com_android_vending'] = num_action_com_android_vending

    if num_action_android_net > 0:
        data['num_intent_action_android_net'] = num_action_android_net

    if num_action_com_android > 0:
        data['num_intent_action_com_android'] = num_action_com_android

    if num_action_other > 0:
        data['num_intent_action_other'] = num_action_other

    if actions > 0:
        data['num_intent_actions'] = len(actions)

    if len(actions) > 0:
        data['intent_actions'] = actions

    data['num_providers'] = len(app.get_providers())
    data['num_libraries'] = len(app.get_libraries())
    data['num_permissions'] = len(app.get_permissions())
    data['num_third_part_permissions'] = len(app.get_requested_third_party_permissions())

    # -------- Requested permissions
    data['permissions'] = []
    requested_permissions = app.get_permissions()
    for x in requested_permissions:
        data['permissions'].append(x)
    # -------- Used permissions
    data['used_permissions'] = {}
    used_permissions = dvmx.get_permissions([])
    for x in used_permissions:
        data['used_permissions'][x] = len(used_permissions[x])

    data['native_code'] = count_native_code(dvmx)
    data['dynamic_code'] = count_dyn_code(dvmx)
    data['reflection'] = count_reflection_code(dvmx)
    data['ascii_obfuscation'] = count_ascii_obfuscation(d)
    try:
        data['version_code'] = app.get_androidversion_code()
    except:
        pass
    target_sdk = app.get_target_sdk_version()
    if target_sdk:
        data['target_sdk'] = app.get_target_sdk_version()
    data['is_valid_APK'] = app.is_valid_APK()

    tags = {}
    intent_objects = []
    intent_consts = []
    intent_consts_all = []
    #package:method
    sensitive_API = {
        'SmsManager:sendTextMessage': 0,
        'URL:openConnection': 0,
        'TelephonyManager:getDeviceId': 0,
        'TelephonyManager:getLine1Number': 0,
        'HttpURLConnection:connect': 0,
        'URLConnection:getInputStream': 0,
        'TelephonyManager:getSubscriberId': 0,
        'WifiManager:getConnectionInfo': 0,
        'TelephonyManager:getSimSerialNumber': 0,
        'ConnectivityManager:getActiveNetworkInfo': 0,
        'LocationManager:getLastKnownLocation': 0,
        'LocationManager:requestLocationUpdate': 0,
        'TelephonyManager:getCellLocation': 0,
        # ------------------------------------
        'ContentResolver:insert': 0,
        'ContentResolver:delete': 0,
        'ContentResolver:query': 0,
        'Context:getFilesDir': 0,
        'Context:openFileOuput': 0,
        'Context:getApplicationInfo': 0,
        'Intent:setDataAndType': 0,
        'Intent:setFlags': 0,
        'Intent:addFlags': 0,
        'Intent:setDataAndType': 0,
        'ActivityManager:getRunningServices': 0,
        'ActivityManager:getMemoryInfo': 0,
        'ActivityManager:restartPackage': 0,
        'PackageManager:getInstalledPackages': 0,
        'TelephonyManager:getNetworkOperator': 0,
        'Process:myPid': 0,
        'Process:killProcess': 0,
        'File:mkdir': 0,
        'File:delete': 0,
        'File:exists': 0,
        'File:ListFiles': 0,
        'WifiManager:isWifiEnabled' : 0,
        'WifiManager:getIpAddress' : 0
        }

    for i in dvmx.get_methods():
        i.create_tags()
        if not i.tags.empty():
            for tag in i.tags.get_list():
                try:
                    count = tags[tag] + 1
                except:
                    count = 1
                tags[tag] = count
        m = i.get_method()
        code = m.get_code()
        if code is not None:
            instructions = code.get_bc().get_instructions()
            for i in instructions:
                try:
                    tkind = i.get_translated_kind()
                    var = m.get_class_name() + " => " + m.get_name() + " => " + i.get_name() + " => " + tkind
                    #print '++++++++++++++++++', var
                    if 'object' in i.get_name() and 'intent' in tkind:
                        intent_objects.append(var)
                    if  'const-string' in i.get_name() and '.intent.' in tkind:
                        intent_consts_all.append(var)
                        intent_consts.append(tkind)

                    for sapi in sensitive_API:
                        sapi_split = sapi.split(':')
                        pckg = sapi_split[0]
                        mthd = sapi_split[1]
                        if pckg in tkind and mthd in tkind:
                            sensitive_API[sapi] = sensitive_API[sapi] + 1

                except AttributeError:
                    pass

    data['sensitive_API'] = sensitive_API

    if len(intent_objects) > 0:
        data['intent_objects'] = intent_objects

    if len(intent_consts) > 0:
        data['intent_consts'] = intent_consts

        num_action_android_intent = 0
        num_action_com_android_vending = 0
        num_action_android_net = 0
        num_action_com_android = 0
        num_action_other = 0

        for const in intent_consts:
            if 'android.intent.action' in const:
                num_action_android_intent += 1
            elif 'com.android.vending' in const:
                num_action_com_android_vending += 1
            elif 'android.net' in const:
                num_action_android_net += 1
            elif 'com.android' in const:
                num_action_com_android += 1
            else:
                num_action_other += 1

        if num_action_android_intent > 0:
            data['num_intent_const_android_intent'] = num_action_android_intent

        if num_action_com_android_vending > 0:
            data['num_intent_const_com_android_vending'] = num_action_com_android_vending

        if num_action_android_net > 0:
            data['num_intent_const_android_net'] = num_action_android_net

        if num_action_com_android > 0:
            data['num_intent_const_com_android'] = num_action_com_android

        if num_action_other > 0:
            data['num_intent_const_other'] = num_action_other

    data['method_tags'] = tags

    data['num_files'] = len(app.get_files())


    incognito_apk = []
    incognito_dex = []
    incognito_sh = []
    incognito_elf = []

    # COMPONENTS: assets and resources components
    files=app.get_files_types()
    for f in files:
        # ------ File extension #
        fileName, fileExtension = os.path.splitext(f)
        try:
            extensions[fileExtension] = extensions[fileExtension] + 1
        except KeyError:
            extensions[fileExtension] = 1

        # ------ Magic number extension
        try:
            #print files[f]
            file_type = None
            for key in file_type_key:
                match = 0
                for token in file_type_key[key]:
                    if token in files[f]:
                        match = match + 1
                if len(file_type_key[key]) is match:
                    file_type = key
            if file_type == None:
                file_type = files[f].split(" ")[0]
            types[file_type] = types[file_type] + 1
        except KeyError:
            types[file_type] = 1

        # ------ Components of interest
        crc = app.get_files_crc32()[f]
        for sub_class_name in FileCoI.FileCoI.__subclasses__():
            coi_type = sub_class_name.__name__
            if coi_type in coi_modules:
                sub_class = sub_class_name(app, fileName, fileExtension, file_type, files[f], f, crc)
                if sub_class.check():
                    components_of_interest.append(sub_class)
                    try:
                        count = num_componenets_of_interest[coi_type] + 1
                    except KeyError:
                        count = 1
                    num_componenets_of_interest[coi_type] = count

        if file_type == 'APK':
            incognito_apk.append(f)

        if file_type == 'DEX' and 'classes' != fileName:
            incognito_dex.append(f)

        if file_type == 'ELF':
            incognito_elf.append(f)

        if file_type == "Text Executable":
            incognito_sh.append(f)


    text_executable_commands = {}
    if incognito_sh:
        regexp = '|'.join(sh_commands)
        pattern = re.compile(regexp)
        for file_path in incognito_sh:
            content = app.get_file(file_path)
            matches = pattern.findall(content)
            for match in matches:
                try:
                    count = text_executable_commands[match]
                except KeyError:
                    count = 0
                text_executable_commands[match] = count + 1
    if text_executable_commands:
        data['text_executable_commands'] = text_executable_commands

    if types:
        data['file'] = types

    if num_componenets_of_interest:
        data['CoIs'] = num_componenets_of_interest

    # TODO: KNOWN SECTIONS: http://link.springer.com/article/10.1007/s10115-011-0393-5#/page-1

    '''
      # feature | description | example
      ---------------------------------
      ========== File Header ==========
      data['e_ehsize']:      Size of this header:               52 (bytes)
      data['e_phentsize']:   Size of program headers:           32 (bytes)
      data['e_phnum']:       Number of program headers:         5
      data['e_shentsize']:   Size of section headers:           40 (bytes)
      data['e_shnum']:       Number of section headers:         21
      data['e_shstrndx']:    Section header string table index: 18
      ==========  Sections ==========
      section['sh_flags']:     Flags of a given section:
          W (write), A (alloc), X (execute), M (merge), S (strings)
          I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)
          O (extra OS processing required) o (OS specific), p (processor specific)
      ==========  Shared Libraries ==========
      data['symbols_shared_libraries']: Relocation information for PLT (Position Independent Code): ioctl, fork, etc.
    '''
    for file_path in incognito_elf:
        content = app.get_file(file_path)
        import StringIO
        steam_content = StringIO.StringIO()
        steam_content.write(content)
        try:
            readelf = ReadElf(steam_content, sys.stdout) #stream

            if readelf:
                data['e_ehsize'] = readelf.elffile.header['e_ehsize']
                data['e_phentsize'] = readelf.elffile.header['e_phentsize']
                data['e_phnum'] = readelf.elffile.header['e_phnum']
                data['e_shentsize'] = readelf.elffile.header['e_shentsize']
                data['e_shnum'] = readelf.elffile.header['e_shnum']
                data['e_shstrndx'] = readelf.elffile.header['e_shstrndx']

                symbols_shared_libraries = [] # Relocation information for PLT (Position Independent Code)
                sections_flags = {}
                for nsec, section in enumerate(readelf.elffile.iter_sections()):

                    # ---------- Relocation information for PLT (Position Independent Code) ----------
                    if isinstance(section, RelocationSection):

                        try:

                            # The symbol table section pointed to in sh_link
                            symtable = readelf.elffile.get_section(section['sh_link'])
                            for rel in section.iter_relocations():
                                if rel['r_info_sym'] == 0:
                                    continue

                                symbol = symtable.get_symbol(rel['r_info_sym'])
                                # Some symbols have zero 'st_name', so instead what's used is
                                # the name of the section they point at
                                if symbol['st_name'] == 0:
                                    symsec = readelf.elffile.get_section(symbol['st_shndx'])
                                    symbol_name = symsec.name
                                else:
                                    symbol_name = symbol.name

                                if symbol_name in elf_symbols_white_list:
                                    symbols_shared_libraries.append(symbol_name)

                        except ELFParseError, e:
                            print 'Waring ELFParseError for', data['package']

                    # ---------- Flags from the section ----------

                    flag = describe_sh_flags(section['sh_flags'])
                    if not flag:
                        continue
                    try:
                        count = sections_flags[flag]
                    except KeyError:
                        count = 0
                    sections_flags[flag] = count + 1

                if sections_flags:
                    data['e_sh_flags'] = sections_flags

                if symbols_shared_libraries:
                    data['symbols_shared_libraries'] = symbols_shared_libraries

        except Exception, e:
            print 'WARNING: cannot read elf', str(e), app.get_filename(), file_path
            readelf = None

    #TODO: merge incognito_dex

    for file_path in incognito_apk:
        content = app.get_file(file_path)
        incognito_apk_data =  extract_static_features(content, True)
        #incognito_apk_data = filter_out_dict(incognito_apk_data, merge_features_white_list)
        data = append_dict(data, incognito_apk_data) # merge_dict(data, incognito_apk_data) # append_dict(data, incognito_apk_data)

    return data


def extract_static_features_details(filename):

    app = apk.APK(filename)

    data = {}
    data['package'] = app.get_package()
    data['main_activity'] = app.get_main_activity()

    data['files'] = []
    for x in app.get_files():
        data['files'].append(x)

    data['activities'] = []
    try:
        activities = app.get_activities()
    except:
        activities = []
    for x in activities:
        data['activities'].append(x)

    data['services'] = []
    for x in app.get_services():
        data['services'].append(x)

    data['receivers'] = []
    for x in app.get_receivers():
        data['receivers'].append(x)

    data['actions'] = []
    if len(app.get_receivers()) > 0:
        for x in get_actions(app):
            data['actions'].append(x)

    data['providers'] = []
    for x in app.get_providers():
        data['providers'].append(x)

    data['permissions'] = []
    for x in app.get_permissions():
        data['permissions'].append(x)

    data['libraries'] = []
    for x in app.get_libraries():
        data['libraries'].append(x)

    return data

def dump_apk_info(filename, log=True):
    if log:
        print >> sys.stderr, filename
        fd = open(filename+'.log', 'aw+')
        app = apk.APK(filename)
        fd.write("<static>")
        fd.write("<package>"+app.get_package()+"</package>\n")
        fd.write("<main>%s</main>\n" % app.get_main_activity())

        fd.write("<files>\n")
        for x in app.get_files():
            fd.write("\t<file>"+x+"</file>\n")
        fd.write("</files>\n")

        fd.write("<activities>\n")
        try:
            activities = app.get_activities()
        except:
            activities = []
        for x in activities:
            fd.write("\t<activity>"+x+"</activity>\n")
        fd.write("</activities>\n")

        fd.write("<services>\n")
        for x in app.get_services():
            fd.write("\t<service>"+x+"</service>\n")
        fd.write("</services>\n")

        fd.write("<receivers>\n")
        for x in app.get_receivers():
            fd.write("\t<receiver>"+x+"</receiver>\n")
        if len(app.get_receivers()) > 0:
            for x in get_actions(app):
                fd.write("\t<action>"+str(x)+"</action>\n")
        fd.write("</receivers>\n")

        fd.write("<providers>\n")
        for x in app.get_providers():
            fd.write("\t<provide>"+x+"</provide>\n")
        fd.write("</providers>\n")

        fd.write("<permissions>\n")
        for x in app.get_permissions():
            fd.write("\t<permission>"+x+"</permission>\n")
        fd.write("</permissions>\n")

        fd.write("<libraries>\n")
        for x in app.get_libraries():
            fd.write("\t<library>"+x+"</library>\n")
        fd.write("</libraries>\n")

        fd.close()

def show_apk_info(filename):
    app = apk.APK(filename)
    app.show()

def infer_name_from_pkg(filename):
    print >> sys.stderr, " * OPENING: %s" % filename
    app = apk.APK(filename)
#    app.show()
    strname = app.get_package()
    print strname
    return strname[-15:] # process name will be most probably == last packagename 16 chars \x00 included


def append_dict(dict1, dict2):

    for key2 in dict2:
        newkey = 'incognito.' + key2
        dict1[newkey] = dict2[key2]
    return dict1


def merge_dict(dict1, dict2):

    ret_dict = {}
    for key1 in dict1:
        common = False
        for key2 in dict2:
            if key1 == key2:
                key = key1
                if isinstance(dict1[key], dict) and isinstance(dict1[key], dict) and dict1[key] and dict2[key]:
                    ret_dict[key] = merge_dict(dict1[key], dict2[key])
                elif isinstance(dict1[key], int) and isinstance(dict1[key], int) and dict1[key] and dict2[key]:
                    ret_dict[key] = dict1[key] + dict2[key]
                elif isinstance(dict1[key], list) and isinstance(dict1[key], list) and dict1[key] and dict2[key]:
                    ret_dict[key] = dict1[key] + dict2[key]
                elif dict1[key1]:
                    ret_dict[key] = dict1[key]
                elif dict2[key]:
                    ret_dict[key] = dict2[key]
                common = True
                break
        if not common:
            ret_dict[key1] = dict1[key1]
        else:
            del dict2[key1]

    ret_dict.update(dict2)
    return ret_dict


def filter_out_dict(dictionary, white_list):
    ret = {}
    for key in white_list:
        if key in dictionary:
            ret[key] = dictionary[key]
    return ret

if __name__ == "__main__":
    if(len(sys.argv) < 1):
        sys.exit()

    filename = check_file(sys.argv[1])
    if filename == -1:
        print "[!]", sys.argv[1], "cannot be accessed"
        sys.exit()

    print "***"
    print infer_name_from_pkg(filename)
    dump_apk_info(filename)
    print ""

    print "***"

    #d1 = {'2':2, '1':1, '3':3, 'd1d2':9, 'd1':6, 'dd':{'dd1':1, 'dd2': 2, 'ddno1': 69}, 'dl':[1,2,3]}
    #d2 = {'2':2, '1':1, '3':3, 'd2d1':9, 'd2':5, 'dd':{'dd1':1, 'dd2': 2, 'ddno2': 69}, 'dl':[2,3,4]}
    #data = merge_dict(d1, d2)
    #print 'merge = ',  data
    #data = filter_out_dict(data, {'dl'})
    #print 'filter = ', data
    #sys.exit(1)

    hls = extract_static_features(sys.argv[1])

    print '-----------------------------', hls


    #feature = 'used_permissions'
    #if feature in hls:
    #    permissions = hls[feature]
    #    print permissions
    #    for p in permissions:
    #        print feature + '.' + p, permissions[p]

    if len(sys.argv) == 3:
        hls1 = hls
        hls2 = extract_static_features(sys.argv[2])
        print '------------------'
        print hls2

        hls_new = merge_dict(hls1, hls2)
        print '------------------'

        print hls_new


    sys.exit(1)


#    show_apk_info(filename)

    if install_apk(filename) == -1:
        print "[!]", filename, "cannot be installed"
        sys.exit()

    print "[*]", filename, "successfully installed"

    if run_apk(filename) == -1:
        print "[!]", filename, "cannot be executed"
        sys.exit()

    print "[*]", filename, "successfully executed"





