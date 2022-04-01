#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Create Certificates
#
# This tool creates certificates which can be used 
# when pairing with a Gamestream PC.
# 

# --- Python standard library ---
from __future__ import unicode_literals
from __future__ import division

import os
import logging
import sys

# AKL main imports
from akl.utils import io

from resources.lib import crypto

logger = logging.getLogger(__name__)

def main():
    try:
        path = sys.argv[1]
        certs_path = io.FileName(path, isdir=True)
        
        print(f'Going to create nvidia.crt and nvidia.key files in directory {path}')
        cert_file = certs_path.pjoin('nvidia.crt')
        key_file = certs_path.pjoin('nvidia.key')

        created = crypto.create_self_signed_cert_with_cryptolib("NVIDIA GameStream Client", cert_file, key_file)
        
        if created: print('Certificate files created')
        else: print('Failed to create certificate files')
    except Exception as ex:
        logger.fatal('Exception in tool', exc_info=ex)

if __name__ == '__main__':
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    sys.path.append(root)
    main()