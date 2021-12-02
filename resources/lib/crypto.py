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

from base64 import b64decode
from base64 import b64encode

# NOTE OpenSSL library will be included in Kodi M****
#      Search documentation about this in Garbear's github repo.
try:
    from OpenSSL import crypto, SSL
    UTILS_OPENSSL_AVAILABLE = True
except:
    UTILS_OPENSSL_AVAILABLE = False

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    UTILS_CRYPTOGRAPHY_AVAILABLE = True
except:
    UTILS_CRYPTOGRAPHY_AVAILABLE = False

try:
    from Crypto.PublicKey import RSA
    from Crypto.Signature import PKCS1_v1_5
    from Crypto.Hash import SHA256
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    UTILS_PYCRYPTO_AVAILABLE = True
except:
    UTILS_PYCRYPTO_AVAILABLE = False
    
logger = logging.getLogger(__name__)

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
def create_self_signed_cert(cert_name, cert_file_path, key_file_path):
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    now    = datetime.now()
    expire = now + timedelta(days=365)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "GL"
    cert.get_subject().ST = "GL"
    cert.get_subject().L = "Kodi"
    cert.get_subject().O = "akl"
    cert.get_subject().OU = "akl"
    cert.get_subject().CN = cert_name
    cert.set_serial_number(1000)
    cert.set_notBefore(now.strftime("%Y%m%d%H%M%SZ").encode())
    cert.set_notAfter(expire.strftime("%Y%m%d%H%M%SZ").encode())
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, str('sha1'))

    logger.debug('Creating certificate file {0}'.format(cert_file_path.getPath()))
    data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    cert_file_path.saveStrToFile(data, 'ascii')

    logger.debug('Creating certificate key file {0}'.format(key_file_path.getPath()))
    data = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
    key_file_path.saveStrToFile(data, 'ascii')

def getCertificatePublicKeyBytes(certificate_data):
    pk_data = getCertificatePublicKey(certificate_data)
    return bytearray(pk_data)

def getCertificatePublicKey(certificate_data):
    cert = crypto.x509.load_pem_x509_certificate(certificate_data, default_backend())
    pk = cert.public_key()
    pk_data = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    return pk_data

def getCertificateSignature(certificate_data):
    cert = crypto.x509.load_pem_x509_certificate(certificate_data, default_backend())
    return cert.signature

def verify_signature(data, signature, certificate_data):
    pk_data = getCertificatePublicKey(certificate_data)
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

    def decrypt(self, enc):
        cipher = AES.new(self.key, AES.MODE_ECB)
        decrypted = cipher.decrypt(str(enc))
        return decrypted