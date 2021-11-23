# -*- coding: utf-8 -*-
#
# Advanced Emulator Launcher: Gamestream server connection objects
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

from os.path import expanduser
import binascii
import uuid
import random
import xml.etree.ElementTree as ET

# --- AEL packages ---
from ael.utils import net, io, text, kodi

# Local modules
import resources.lib.crypto as crypto

logger = logging.getLogger(__name__)

# #################################################################################################
# #################################################################################################
# Gamestream
# #################################################################################################
# #################################################################################################
class GameStreamServer(object):
    
    def __init__(self, host:str, certificates_path:io.FileName, debug_mode = False):
        self.host = host
        self.unique_id = random.getrandbits(16)
        self.debug_mode = debug_mode

        if certificates_path:
            self.certificates_path = certificates_path
            self.certificate_file_path = self.certificates_path.pjoin('nvidia.crt')
            self.certificate_key_file_path = self.certificates_path.pjoin('nvidia.key')
        else:
            self.certificates_path = io.FileName('')
            self.certificate_file_path = io.FileName('')
            self.certificate_key_file_path = io.FileName('')

        logger.debug('GameStreamServer() Using certificate key file {}'.format(self.certificate_key_file_path.getPath()))
        logger.debug('GameStreamServer() Using certificate file {}'.format(self.certificate_file_path.getPath()))

        self.pem_cert_data = None
        self.key_cert_data = None

    def _perform_server_request(self, end_point,  useHttps=True, parameters:dict = None):
        
        if useHttps:
            url = "https://{0}:47984/{1}?uniqueid={2}&uuid={3}".format(self.host, end_point, self.unique_id, uuid.uuid4().hex)
        else:
            url = "http://{0}:47989/{1}?uniqueid={2}&uuid={3}".format(self.host, end_point, self.unique_id, uuid.uuid4().hex)

        if parameters:
            for key, value in parameters.items():
                url = url + "&{0}={1}".format(key, value)

        handler = net.HTTPSClientAuthHandler(self.certificate_key_file_path.getPath(), self.certificate_file_path.getPath())
        page_data = net.get_URL_using_handler(url, handler)
    
        if page_data is None:
            return None
        
        root = ET.fromstring(page_data)
        if self.debug_mode:
            logger.debug(ET.tostring(root,encoding='utf8',method='xml'))
       
        return root

    def connect(self):
        logger.debug('Connecting to gamestream server {}'.format(self.host))
        self.server_info = self._perform_server_request("serverinfo")
        
        if not self.is_connected():
            self.server_info = self._perform_server_request("serverinfo", False)
        
        return self.is_connected()

    def is_connected(self):
        if self.server_info is None:
            logger.debug('No succesfull connection to the server has been made')
            return False

        if self.server_info.find('state') is None:
            logger.debug('Server state {0}'.format(self.server_info.attrib['status_code']))
        else:
            logger.debug('Server state {0}'.format(self.server_info.find('state').text))

        return self.server_info.attrib['status_code'] == '200'

    def get_server_version(self) -> text.VersionNumber:
        appVersion = self.server_info.find('appversion')
        return text.VersionNumber(appVersion.text)
    
    def get_uniqueid(self):
        uniqueid = self.server_info.find('uniqueid').text
        return uniqueid
    
    def get_hostname(self):
        hostname = self.server_info.find('hostname').text
        return hostname

    def generatePincode(self):
        i1 = random.randint(1, 9)
        i2 = random.randint(1, 9)
        i3 = random.randint(1, 9)
        i4 = random.randint(1, 9)
    
        return '{0}{1}{2}{3}'.format(i1, i2, i3, i4)

    def is_paired(self):
        if not self.is_connected():
            logger.warning('Connect first')
            return False

        pairStatus = self.server_info.find('PairStatus')
        return pairStatus.text == '1'

    def pairServer(self, pincode):
        if not self.is_connected():
            logger.warning('Connect first')
            return False

        version = self.get_server_version()
        logger.info("Pairing with server generation: {0}".format(version.getFullString()))

        majorVersion = version.getMajor()
        if majorVersion >= 7:
            # Gen 7+ uses SHA-256 hashing
            hashAlgorithm = crypto.HashAlgorithm(256)
        else:
            # Prior to Gen 7, SHA-1 is used
            hashAlgorithm = crypto.HashAlgorithm(1)
        logger.debug('Pin {0}'.format(pincode))

        # Generate a salt for hashing the PIN
        salt = crypto.randomBytes(16)
        # Combine the salt and pin
        saltAndPin = salt + bytearray(pincode, 'utf-8')
        # Create an AES key from them
        aes_cypher = crypto.AESCipher(saltAndPin, hashAlgorithm)

        # get certificates ready
        logger.debug('Getting local certificate files')
        client_certificate      = self.getCertificateBytes()
        client_key_certificate  = self.getCertificateKeyBytes()
        certificate_signature   = crypto.getCertificateSignature(client_certificate)

        # Start pairing with server
        logger.debug('Start pairing with server')
        pairing_result = self._perform_server_request('pair', False, {
            'devicename': 'ael', 
            'updateState': 1, 
            'phrase': 'getservercert', 
            'salt': binascii.hexlify(salt),
            'clientcert': binascii.hexlify(client_certificate)
            })

        if pairing_result is None:
            logger.error('Failed to pair with server. No XML received.')
            return False

        isPaired = pairing_result.find('paired').text
        if isPaired != '1':
            logger.error('Failed to pair with server. Server returned failed state.')
            return False

        server_cert_data = pairing_result.find('plaincert').text
        if server_cert_data is None:
            logger.error('Failed to pair with server. A different pairing session might be in progress.')
            return False
        
        # Generate a random challenge and encrypt it with our AES key
        challenge = crypto.randomBytes(16)
        encrypted_challenge = aes_cypher.encryptToHex(challenge)
        
        # Send the encrypted challenge to the server
        logger.debug('Sending encrypted challenge to the server')
        pairing_challenge_result = self._perform_server_request('pair', False, {
            'devicename': 'ael', 
            'updateState': 1, 
            'clientchallenge': encrypted_challenge })
        
        if pairing_challenge_result is None:
            logger.error('Failed to pair with server. No XML received.')
            return False

        isPaired = pairing_challenge_result.find('paired').text
        if isPaired != '1':
            logger.error('Failed to pair with server. Server returned failed state.')
            self._perform_server_request('unpair', False)
            return False

        # Decode the server's response and subsequent challenge
        logger.debug('Decoding server\'s response and challenge response')
        server_challenge_hex = pairing_challenge_result.find('challengeresponse').text
        server_challenge_bytes = bytearray.fromhex(server_challenge_hex)
        server_challenge_decrypted = aes_cypher.decrypt(server_challenge_bytes)
        
        server_challenge_firstbytes = server_challenge_decrypted[:hashAlgorithm.digest_size()]
        server_challenge_lastbytes  = server_challenge_decrypted[hashAlgorithm.digest_size():hashAlgorithm.digest_size()+16]

        # Using another 16 bytes secret, compute a challenge response hash using the secret, our cert sig, and the challenge
        client_secret               = crypto.randomBytes(16)
        challenge_response          = server_challenge_lastbytes + certificate_signature + client_secret
        challenge_response_hashed   = hashAlgorithm.hash(challenge_response)
        challenge_response_encrypted= aes_cypher.encryptToHex(challenge_response_hashed)
        
        # Send the challenge response to the server
        logger.debug('Sending the challenge response to the server')
        pairing_secret_response = self._perform_server_request('pair', False, {
            'devicename': 'ael', 
            'updateState': 1, 
            'serverchallengeresp': challenge_response_encrypted })
        
        if pairing_secret_response is None:
            logger.error('Failed to pair with server. No XML received.')
            return False

        isPaired = pairing_secret_response.find('paired').text
        if isPaired != '1':
            logger.error('Failed to pair with server. Server returned failed state.')
            self._perform_server_request('unpair', False)
            return False

        # Get the server's signed secret
        logger.debug('Verifiying server signature')
        server_secret_response  = bytearray.fromhex(pairing_secret_response.find('pairingsecret').text)
        server_secret           = server_secret_response[:16]
        server_signature        = server_secret_response[16:272]

        server_cert = server_cert_data.decode('hex')
        is_verified = crypto.verify_signature(str(server_secret), server_signature, server_cert)

        if not is_verified:
            # Looks like a MITM, Cancel the pairing process
            logger.error('Failed to verify signature. (MITM warning)')
            self._perform_server_request('unpair', False)
            return False

        # Ensure the server challenge matched what we expected (aka the PIN was correct)
        logger.debug('Confirming PIN with entered value')
        server_cert_signature       = crypto.getCertificateSignature(server_cert)
        server_secret_combination   = challenge + server_cert_signature + server_secret
        server_secret_hashed        = hashAlgorithm.hash(server_secret_combination)

        if server_secret_hashed != server_challenge_firstbytes:
            # Probably got the wrong PIN
            logger.error("Wrong PIN entered")
            self._perform_server_request('unpair', False)
            return False

        logger.debug('Pin is confirmed')

        # Send the server our signed secret
        logger.debug('Sending server our signed secret')
        signed_client_secret = crypto.sign_data(client_secret, client_key_certificate)
        client_pairing_secret = client_secret + signed_client_secret

        client_pairing_secret_response = self._perform_server_request('pair', False, {
            'devicename': 'ael', 
            'updateState': 1, 
            'clientpairingsecret':  binascii.hexlify(client_pairing_secret)})
        
        isPaired = client_pairing_secret_response.find('paired').text
        if isPaired != '1':
            logger.error('Failed to pair with server. Server returned failed state.')
            self._perform_server_request('unpair', False)
            return False

        # Do the initial challenge over https
        logger.debug('Initial challenge again')
        pair_challenge_response = self._perform_server_request('pair', True, {
            'devicename': 'ael', 
            'updateState': 1, 
            'phrase':  'pairchallenge'})

        isPaired = pair_challenge_response.find('paired').text
        if isPaired != '1':
            logger.error('Failed to pair with server. Server returned failed state.')
            self._perform_server_request('unpair', False)
            return False

        return True

    def getApps(self):
        apps_response = self._perform_server_request('applist', True)
        if apps_response is None:
            kodi.notify_error('Failure to connect to GameStream server')
            return []

        appnodes = apps_response.findall('App')
        apps = []
        for appnode in appnodes:
            app = {}
            for appnode_attr in appnode:
                if len(list(appnode_attr)) > 1:
                    continue
                
                xml_text = appnode_attr.text if appnode_attr.text is not None else ''
                xml_text = text.unescape_XML(xml_text)
                xml_tag  = appnode_attr.tag
           
                app[xml_tag] = xml_text
            apps.append(app)

        return apps

    def getCertificateBytes(self):
        if self.pem_cert_data:
            return self.pem_cert_data

        if not self.certificate_file_path.exists():
            logger.info('Client certificate file does not exist. Creating')
            crypto.create_self_signed_cert("NVIDIA GameStream Client", self.certificate_file_path, self.certificate_key_file_path)

        logger.info('Loading client certificate data from {0}'.format(self.certificate_file_path.getPath()))
        self.pem_cert_data = self.certificate_file_path.loadFileToStr('ascii')

        return str(self.pem_cert_data)

    def getCertificateKeyBytes(self):
        if self.key_cert_data:
            return self.key_cert_data

        if not self.certificate_key_file_path.exists():
            logger.info('Client certificate file does not exist. Creating')
            crypto.create_self_signed_cert("NVIDIA GameStream Client", self.certificate_file_path, self.certificate_key_file_path)
        logger.info('Loading client certificate data from {0}'.format(self.certificate_key_file_path.getPath()))
        self.key_cert_data = self.certificate_key_file_path.loadFileToStr('ascii')

        return str(self.key_cert_data)

    def validate_certificates(self):
        if self.certificate_file_path.exists() and self.certificate_key_file_path.exists():
            logger.debug('validate_certificates(): Certificate files exist. Done')
            return True

        certificate_files = self.certificates_path.scanFilesInPath('*.crt')
        key_files = self.certificates_path.scanFilesInPath('*.key')

        if len(certificate_files) < 1:
            logger.warning('validate_certificates(): No .crt files found at given location.')
            return False

        if not self.certificate_file_path.exists():
            logger.debug('validate_certificates(): Copying .crt file to nvidia.crt')
            certificate_files[0].copy(self.certificate_file_path)

        if len(key_files) < 1:
            logger.warning('validate_certificates(): No .key files found at given location.')
            return False

        if not self.certificate_key_file_path.exists():
            logger.debug('validate_certificates(): Copying .key file to nvidia.key')
            key_files[0].copy(self.certificate_key_file_path)

        return True

    @staticmethod
    def try_to_resolve_path_to_nvidia_certificates():
        home = expanduser("~")
        homePath = io.FileName(home)

        possiblePath = homePath.pjoin('Moonlight/')
        if possiblePath.exists():
            return possiblePath.getPath()

        possiblePath = homePath.pjoin('Limelight/')
        if possiblePath.exists():
            return possiblePath.getPath()

        return homePath.getPath()