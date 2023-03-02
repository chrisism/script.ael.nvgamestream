#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Pairing with Sunshine / Nvidia Gamestream PC
#
# This tool must be called with two parameters, host and path where the certificates are found.
# Example: >

#
# Certificate files should be named '<name>.crt' and '<name>.key'.
#
# When started this tool will show a unique pincode which you need to enter in a dialog
# on your computer which is running Nvidia Geforce Experience. When done correctly it will
# pair up with that computer and generate certificates needed to keep on communicating with
# the geforce experience computer. These certificates can be used in a Gamestream Launcher.
#
# pip install -r requirements
#
import sys, os
# AKL main imports
from akl.utils import io

# Local modules
try:
    from resources.lib.gamestream import GameStreamServer
except:
    from script_akl_nvgamestream.resources.lib.gamestream import GameStreamServer

def pair(host:str, path:str):

    certs_path = io.FileName(path)
    print(f"Going to connect with '{host}'")

    gs_info = GameStreamServer.create_new_connection_info("TEST", host)
    gs = GameStreamServer(gs_info)
    if not gs.connect():
        print('Could not connect to gamestream server')
        return input

    connection_name = gs.get_hostname()
    gs_info = GameStreamServer.create_new_connection_info(connection_name, host)
    
    cert_filepath = certs_path.pjoin("nvidia.crt")
    cert_key_filepath = certs_path.pjoin("nvidia.key")
    gs_info["cert_key_file"] = cert_key_filepath.getPath()
    gs_info["cert_file"] = cert_filepath.getPath()

    server = GameStreamServer(gs_info)
    
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

    connection_info = {
        "name": server.name,
        "unique_id": server.unique_id,
        "host": server.host,
        "paired": server.is_paired(),
        "cert_file": server.certificate_file_path.getPath(),
        "cert_key_file": server.certificate_key_file_path.getPath()
    }

    connection_info_file = certs_path.pjoin(f"{server.name}.conf")
    connection_info_file.writeJson(connection_info)

def main():
    host = sys.argv[1]
    path = sys.argv[2]

    pair(host, path)

if __name__ == '__main__':

    root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    sys.path.append(root)
    main()