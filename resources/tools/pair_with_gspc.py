#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Pairing with Nvidia Gamestream PC
#
# This tool must be called with two parameters, host and path where the certificates are found.
# Example: >python pair_with_nvidia.py 192.168.1.99 c:\games\gamestream\
#
# Certificate files should be named 'nvidia.crt' and 'nvidia.key'.
#
# When started this tool will show a unique pincode which you need to enter in a dialog
# on your computer which is running Nvidia Geforce Experience. When done correctly it will
# pair up with that computer and generate certificates needed to keep on communicating with
# the geforce experience computer. These certificates can be used in a Gamestream Launcher.
#
# pip install -r requirements
#
#from __future__ import unicode_literals
import sys, os
# AKL main imports
from akl.utils import io

# Local modules
from resources.lib.gamestream import GameStreamServer

def pair(host:str, path:str):

    certs_path = io.FileName(path)
    print(f"Going to connect with '{host}'")

    server = GameStreamServer(host, certs_path)
    succeeded = False
    try:
        succeeded = server.connect()
    except:
        print("Error")

    if not succeeded:
        print(f"Connection to {host} failed")
        exit

    print(f"Connection to {host} succeeded")

    if server.is_paired():
        print(f"Already paired with host {host}. Stopping pairing process")
        exit

    pincode = server.generatePincode()

    print("Start pairing process")
    print(f"Open up the Gamestream server and when asked insert the following PIN code: {pincode}")
    paired = server.pairServer(pincode)

    if not paired:
        print(f"Pairing with {host} failed")
    else:
        print(f"Pairing with {host} succeeded")

def main():
    host = sys.argv[1]
    path = sys.argv[2]

    pair(host, path)

if __name__ == '__main__':
    main()