#!/usr/bin/python

import sys
import zipfile
import datetime
from M2Crypto import SMIME, X509, BIO


def get_certificate(self, filename):
    cert = chilkat.CkCert()
    f = self.get_file(filename)
    data = chilkat.CkByteData()
    data.append2(f, len(f))
    success = cert.LoadFromBinary(data)
    return success, cert

def calculate_difference(FILENAME):

    signature_date = None
    certificate_date = None
    certificate_subject = None

    try:
        # open an apk or jar as a ZipFile
        Z = zipfile.ZipFile(open(FILENAME, 'rb'))
    except:
        print 'WARNING: Not a ZipFile', FILENAME
        return signature_date, certificate_date, certificate_subject

    for name in Z.namelist():       
        # certificate file
        if (name.endswith("DSA") or (name.endswith("RSA"))):    
            try:                                    
                with Z.open(name) as f:   
                    fileBytes = f.read()
            except:
                print 'WARNING: Bad ZipFile', name
                return signature_date, certificate_date, certificate_subject
            # encode binary data to base64 and wrap it in a PKCS7 envelop            
            sig = '-----BEGIN PKCS7-----\n' + fileBytes.encode('base64') + '-----END PKCS7-----\n'                  

            # load certificate into a p7 object through BIO I/O buffer:
            buf = BIO.MemoryBuffer(sig)     
            p7 = SMIME.load_pkcs7_bio(buf)  
            sk = X509.X509_Stack()
            signers = p7.get0_signers(sk)
            # get X509 certificate
            certificate = signers[0]

            dateString = certificate.get_not_before()               
            certificate_date = datetime.datetime.strptime(str(dateString), '%b %d %H:%M:%S %Y %Z')
            certificate_subject = certificate.get_subject()                          

        # signature file
        if (name.endswith("SF")):
            try:
                signature_date = datetime.datetime(*Z.getinfo(name).date_time[0:6])
            except ValueError:
                signature_date = datetime.datetime(Z.getinfo(name).date_time[0], 1, 1)

    Z.close()
    return signature_date, certificate_date, certificate_subject

if __name__ == "__main__":

    try:
        SCRIPT, FILENAME = sys.argv
    except ValueError as e:
        raise SystemExit('Usage: {0} <signed-apk-or-jar-file>'.format(sys.argv[0]))
																					
    signature_date, certificate_date, certificate_subject = calculate_difference(FILENAME)

    print 'Certificate:', certificate_subject

    try:
        print '\n* Certificate creation date (UTC time): {0}'.format(certificate_date)
        print '* Signature file date seems to be (system time): {0}'.format(signature_date)
        DIF = signature_date - certificate_date
    except:
        raise SystemExit('Usage: {0} <signed-apk-or-jar-file>'.format(sys.argv[0]))
		
    if (DIF.days == 0 or DIF.days == -1):
        try:			
            TIMEZONE, REF_SECONDS = get_timezone(DIF.seconds if (DIF.days == 0) else DIF.seconds - 86400)			
            print "\nIf we assume they were created at the same moment, the developer's time zone is:", TIMEZONE
            print_accuracy(DIF.seconds if (DIF.days == 0) else DIF.seconds - 86400, REF_SECONDS, certificate_date, signature_date)	
        except:
            print "\nNo possible conclusion."					
    else: 
        print "\nNo possible conclusion."	