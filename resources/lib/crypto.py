# -*- coding: utf-8 -*-
#
# Advanced Kodi Launcher: Crytpo utils
#
# Copyright (c) Chrisism <crizizz@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# --- Python standard library ---
from __future__ import unicode_literals
from __future__ import division

import logging
import hashlib
import binascii
from datetime import timedelta
from datetime import datetime

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    UTILS_CRYPTOGRAPHY_AVAILABLE = True
except:
    UTILS_CRYPTOGRAPHY_AVAILABLE = False

try:
    from OpenSSL import crypto, SSL
    UTILS_OPENSSL_AVAILABLE = True
except:
    UTILS_OPENSSL_AVAILABLE = False

try:
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Signature import PKCS1_v1_5
    from Cryptodome.Hash import SHA256
    from Cryptodome.Cipher import AES, PKCS1_v1_5 as PKCS1_v1_5_c
    from Cryptodome.Random import get_random_bytes
    from Cryptodome.Util.asn1 import DerSequence
    UTILS_PYCRYPTO_AVAILABLE = True
except:
    UTILS_PYCRYPTO_AVAILABLE = False

# --- AKL packages ---
from akl.utils import io, kodi
from akl.executors import WindowsExecutor, LinuxExecutor, OSXExecutor, AndroidExecutor

logger = logging.getLogger(__name__)

CREATE_WITH_DOME      = 'PYCRYPTODOME'
CREATE_WITH_CRYPTOLIB = 'CRYPTO'
CREATE_WITH_PYOPENSSL = 'PYSSL'
CREATE_WITH_OPENSSL   = 'OPENSSL'

# #################################################################################################
# #################################################################################################
# Cryptographic utilities
# #################################################################################################
# #################################################################################################

#
# Creates a new self signed certificate base on OpenSSL PEM format.
# cert_name: the CN value of the certificate
# cert_file_path: the path to the .crt file of this certificate
# key_file_paht: the path to the .key file of this certificate
#
def create_self_signed_cert(cert_name, cert_file_path:io.FileName, key_file_path:io.FileName, create_type=CREATE_WITH_OPENSSL) -> bool:
    if create_type == CREATE_WITH_DOME:
        return create_self_signed_cert_with_cryptodome(cert_name, cert_file_path, key_file_path)
    if create_type == CREATE_WITH_CRYPTOLIB:
        return create_self_signed_cert_with_cryptolib(cert_name, cert_file_path, key_file_path)
    if create_type == CREATE_WITH_PYOPENSSL:
        return create_self_signed_cert_with_pyopenssl(cert_name, cert_file_path, key_file_path)
    if create_type == CREATE_WITH_OPENSSL:
        return create_self_signed_cert_with_openssl(cert_name, cert_file_path, key_file_path)
    return False

def create_self_signed_cert_with_cryptodome(cert_name, cert_file_path:io.FileName, key_file_path:io.FileName) -> bool:
    rsakey = RSA.generate(2048)
    public_key = rsakey.public_key()

    data = public_key.export_key()
    data_str = data.decode('ascii')
    cert_file_path.saveStrToFile(data_str, encoding='ascii')

    private_key_data = rsakey.export_key()
    key_file_path.saveStrToFile(private_key_data, encoding='ascii')
    return True
    
def create_self_signed_cert_with_openssl(cert_name, cert_file_path:io.FileName, key_file_path:io.FileName) -> bool:
    executor = None
    logFile = kodi.getAddonDir().pjoin(f'create_cert_{datetime.now().timestamp()}.txt')
    logFile = io.FileName(logFile.getPathTranslated())
    if io.is_windows(): executor = WindowsExecutor(logFile, False, False)
    elif io.is_android(): executor = LinuxExecutor(logFile, False)#AndroidExecutor()
    elif io.is_linux(): executor = LinuxExecutor(logFile, False)
    elif io.is_osx(): executor = OSXExecutor(logFile)
    else: return False
    
    args =  "req -x509 -newkey rsa:2048 -nodes "
    args += f"-keyout {key_file_path.getPathTranslated()} "
    args += f"-out {cert_file_path.getPathTranslated()} -sha1 -days 3650 "
    args += f'-subj "/C=GL/ST=GL/L=KODI/O=AKL/OU=AKL/CN={cert_name}"'

    executor.execute('openssl', args, False)

    return cert_file_path.exists()
    
def create_self_signed_cert_with_pyopenssl(cert_name, cert_file_path:io.FileName, key_file_path:io.FileName) -> bool:
        # create a key pair    
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "GL"
        cert.get_subject().ST = "GL"
        cert.get_subject().L = "KODI"
        cert.get_subject().O = "AKL"
        cert.get_subject().OU = "AKL"
        cert.get_subject().CN = cert_name
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha1')

        cert_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        cert_file_path.open('wb')
        cert_file_path.write(cert_data)
        cert_file_path.close()

        key_data  = crypto.dump_certificate(crypto.FILETYPE_PEM, key)
        key_file_path.open('wb')
        key_file_path.write(key_data)
        key_file_path.close()
        return True

def create_self_signed_cert_with_cryptolib(cert_name, cert_file_path:io.FileName, key_file_path:io.FileName) -> bool:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    
    now    = datetime.utcnow()
    expire = now + timedelta(days=365*10)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"GL"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"GL"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"KODI"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"AKL"),
        x509.NameAttribute(NameOID.COMMON_NAME, cert_name)
    ])
    issuer = subject
        
    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(subject)
    cert_builder = cert_builder.issuer_name(issuer)
    cert_builder = cert_builder.public_key(key.public_key())
    cert_builder = cert_builder.not_valid_before(now)
    cert_builder = cert_builder.not_valid_after(expire) 
    cert_builder = cert_builder.serial_number(10101010)

    # Sign our certificate with our private key
    cert = cert_builder.sign(key, hashes.SHA1(), default_backend())

    logger.debug(f'Creating certificate file {cert_file_path.getPath()}')
    data = cert.public_bytes(serialization.Encoding.PEM)
    data_str = data.decode('ascii')
    cert_file_path.saveStrToFile(data_str, encoding='ascii')

    logger.debug(f'Creating certificate key file {key_file_path.getPath()}')
    data = key.private_bytes(
        serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())

    data_str = data.decode('ascii')
    key_file_path.saveStrToFile(data_str, encoding='ascii')
    return True

def get_certificate_public_key(certificate_data:bytes):
    rsa_key = RSA.importKey(certificate_data) 
    pub_key = rsa_key.publickey()
    pk_data = pub_key.export_key()

    return pk_data

def get_certificate_signature(certificate_data:bytes) -> bytes:
    #c = x509.load_pem_x509_certificate(certificate_data, default_backend())
    #return cert.signature
    cert_data_str   = certificate_data.decode()
    lines           = cert_data_str.replace(" ",'').split()
    cert_der        = binascii.a2b_base64("".join(lines[1:-1]))

    #cert = DerSequence()
    #cert.decode(cert_der)
    #tbsCertificate = DerSequence()
    #tbsCertificate.decode(cert[0])
    #signature = cert[2][len(cert[2])-256:]
    
    signature = cert_der[len(cert_der)-256:]
    return signature

def verify_signature(data:bytes, signature:bytes, certificate_data:bytes):
    pk_data = get_certificate_public_key(certificate_data)
    rsakey = RSA.importKey(pk_data) 
    signer = PKCS1_v1_5.new(rsakey) 
    
    digest = SHA256.new() 
    digest.update(data)

    if signer.verify(digest, signature):
        return True

    return False

def sign_data(data, key_certificate):
    rsakey = RSA.importKey(key_certificate) 
    signer = PKCS1_v1_5.new(rsakey) 
    digest = SHA256.new() 
        
    digest.update(data) 
    sign = signer.sign(digest) 

    return sign

def randomBytes(size):
    return get_random_bytes(size)

class HashAlgorithm(object):
    def __init__(self, shaVersion):
        self.shaVersion = shaVersion
        if self.shaVersion == 256:
            self.hashLength = 32
        else:
            self.hashLength = 20
       
    def _algorithm(self):

        if self.shaVersion == 256:
            return hashlib.sha256()
        else:
            return hashlib.sha1()

    def hash(self, value):
        algorithm = self._algorithm()
        algorithm.update(value)
        hashedValue = algorithm.digest()
        return hashedValue

    def hashToHex(self, value):
        hashedValue = self.hash(value)
        return binascii.hexlify(hashedValue)

    def digest_size(self):
        return self.hashLength

# Block size in bytes.
BLOCK_SIZE = 16

class AESCipher(object):

    def __init__(self, key, hashAlgorithm):
        
        keyHashed = hashAlgorithm.hash(key)
        truncatedKeyHashed = keyHashed[:16]

        self.key = truncatedKeyHashed

    def encrypt(self, raw):
        cipher = AES.new(self.key, AES.MODE_ECB)
        encrypted = cipher.encrypt(raw)
        return encrypted

    def encryptToHex(self, raw):
        encrypted = self.encrypt(raw)
        return binascii.hexlify(encrypted)

    def decrypt(self, enc: bytearray):
        cipher = AES.new(self.key, AES.MODE_ECB)
        
        decrypted = cipher.decrypt(enc)
        return decrypted
