# -*- coding: utf-8 -*-
#
# Advanced Kodi Launcher: Nvidia gamestream scanner implementation
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
import typing
import collections
import json

# --- Kodi packages --
import xbmcgui

# --- AKL packages ---
from akl import report, api
from akl.utils import kodi, io

from akl.scanners import RomScannerStrategy, ROMCandidateABC

# Local modules
from resources.lib.gamestream import GameStreamServer
from resources.lib import crypto, helpers

logger = logging.getLogger(__name__)
        
class GameStreamCandidate(ROMCandidateABC):
    
    def __init__(self, game_data):
        self.game_data = game_data
        super(GameStreamCandidate, self).__init__()
        
    def get_ROM(self) -> api.ROMObj:
        rom = api.ROMObj()
        rom.set_name(self.get_name())
        scanned_data = {
            'gstreamid': self.get_game_id(),
            'gamestream_name': self.get_name(), # so that we always have the original name
            'gstream_xml': json.dumps(self.game_data),
            'scanned_with': kodi.get_addon_id(),
            'scanner_version': kodi.get_addon_version()
        }
        rom.set_scanned_data(scanned_data)
        return rom
        
    def get_sort_value(self):
        return self.game_data['AppTitle']
    
    def get_game_id(self):
        return self.game_data['ID']
    
    def get_name(self):
        return self.game_data['AppTitle']
    
class NvidiaStreamScanner(RomScannerStrategy):
    
    # --------------------------------------------------------------------------------------------
    # Core methods
    # --------------------------------------------------------------------------------------------
    def get_name(self) -> str: return 'Nvidia Gamestream scanner'
    
    def get_scanner_addon_id(self) -> str: 
        addon_id = kodi.get_addon_id()
        return addon_id
            
    def load_settings(self):
        super().load_settings()
        if "selected_connection" in self.scanner_settings and \
            self.scanner_settings["selected_connection"]:
            connection_info_file = io.FileName(self.scanner_settings["selected_connection"])
            self.connection_info = connection_info_file.readJson()
            self.scanner_settings.update(self.connection_info)

    def _configure_get_wizard(self, wizard) -> kodi.WizardDialog:
        logging.debug(f'Has Crypto: "{crypto.UTILS_CRYPTOGRAPHY_AVAILABLE}"')
        logging.debug(f'Has PyCrypto: "{crypto.UTILS_PYCRYPTO_AVAILABLE}"')
        logging.debug(f'Has OpenSSL: "{crypto.UTILS_OPENSSL_AVAILABLE}"')
     
        info_txt  = ('To pair with your Gamestream Computer we need to make use of valid certificates.\n'
                    'Depending on OS and libraries we might not be able to create certificates directly from within Kodi. '
                    'You can always create them manually with external tools/websites.\n'
                    'Please read the documentation or wiki for details how to create them if needed.')

        options = {}
        options['IMPORT'] = 'Import existing (or create manually)'
        options[crypto.CREATE_WITH_CRYPTOLIB] = f'Use cryptography library (Available: {"yes" if crypto.UTILS_CRYPTOGRAPHY_AVAILABLE else "no"})'
        options[crypto.CREATE_WITH_PYOPENSSL] = f'Use OpenSSL library (Available: {"yes" if crypto.UTILS_OPENSSL_AVAILABLE else "no"}, DEPRECATED)'
        options[crypto.CREATE_WITH_OPENSSL]   = f'Execute OpenSSL command'
        
        wizard = kodi.WizardDialog_DictionarySelection(wizard, 'selected_connection', 
            'Select configured connection', self._wizard_get_available_connections())

        # If selected to create a new connection
        wizard = kodi.WizardDialog_Dummy(wizard, 'pincode', None, 
            self._wizard_generate_pair_pincode, self._wizard_creating_new_connection)
        wizard = kodi.WizardDialog_Dummy(wizard, 'unique_id', None, 
            self._wizard_generate_connection_uid, self._wizard_creating_new_connection)
            
        wizard = kodi.WizardDialog_Input(wizard, 'host', 'Gamestream Server',
            xbmcgui.INPUT_IPADDRESS, self._wizard_validate_gamestream_server_connection, 
            self._wizard_creating_new_connection)
        wizard = kodi.WizardDialog_Keyboard(wizard, 'connection_name', 'Connection name', 
            None, self._wizard_creating_new_connection)
        wizard = kodi.WizardDialog_Input(wizard, 'unique_id', 'Client Unique ID', 
            1, None, self._wizard_creating_new_connection)
        wizard = kodi.WizardDialog_FormattedMessage(wizard, 'dummy', 'Pairing with Gamestream PC',
            info_txt, None, self._wizard_creating_new_connection)       
        wizard = kodi.WizardDialog_DictionarySelection(wizard, 'cert_action', 'How to apply certificates',
            options, None, self._wizard_creating_new_connection)
        wizard = kodi.WizardDialog_FileBrowse(wizard, 'certificates_paths', 'Select location to store certificates', 
            0, '', 'files', self._wizard_create_certificates, self._wizard_wants_to_create_certificate) 
        wizard = helpers.WizardDialog_FileBrowseMultiple(wizard, 'certificates_paths', 'Select certificate files', 
            1, '', 'files', self._wizard_validate_nvidia_certificates, self._wizard_wants_to_import_certificate) 

        # if needed to be paired  
        pair_txt =  'We are going to connect with the Gamestream PC.\n'
        pair_txt += 'On your Gamestream PC, once requested, insert the following PIN code: [B]{}[/B].\n'
        pair_txt += 'Press OK to start pairing process.'
        wizard = kodi.WizardDialog_FormattedMessage(wizard, 'pincode', 'Pairing with Gamestream PC',        
            pair_txt, self._wizard_start_pairing_with_server, self._wizard_is_not_paired)
        
        pair_success_txt =  'Plugin is successfully paired with the Gamestream PC.\n'
        pair_success_txt += 'You now can scan/launch games with this connection.'
        wizard = kodi.WizardDialog_FormattedMessage(wizard, 'ispaired', 'Pairing with Gamestream PC',
            pair_success_txt, None, self._wizard_is_paired)

        pair_fail_txt =  'Unfortunately we were not able to pair with the Gamestream PC.\n'
        pair_fail_txt += 'Inspect the logs for more details.'
        wizard = kodi.WizardDialog_FormattedMessage(wizard, 'ispaired', 'Pairing with Gamestream PC',
            pair_fail_txt, None, self._wizard_is_not_paired)
       
        return wizard
      
    def _configure_post_wizard_hook(self):
        store_connection = False
        if self.scanner_settings["selected_connection"] == "NONE":
            store_connection = True

        if store_connection:
            gs = self._get_gamestream_server_from_scanner_settings(self.scanner_settings)
            connection_path = gs.store_connection_info()
            self.scanner_settings["selected_connection"] = connection_path
 
        self.scanner_settings.pop("ispaired")
        self.scanner_settings.pop("pincode")
        self.scanner_settings.pop("dummy")
        self.scanner_settings.pop("certificates_paths")
        self.scanner_settings.pop("cert_action")
        self.scanner_settings.pop("server_uuid")
        self.scanner_settings.pop("host")
        self.scanner_settings.pop("connection_name")
        self.scanner_settings.pop("unique_id")
        self.scanner_settings.pop("cert_file")
        self.scanner_settings.pop("cert_key_file")
       
        return True
    
    # wizard slide conditions
    def _wizard_wants_to_create_certificate(self, item_key, properties) -> bool:
        if not 'cert_action' in properties:
            return False
        return properties['cert_action'] in [
            crypto.CREATE_WITH_CRYPTOLIB, 
            crypto.CREATE_WITH_PYOPENSSL, 
            crypto.CREATE_WITH_OPENSSL]

    def _wizard_wants_to_import_certificate(self, item_key, properties)  -> bool:
        if not 'cert_action' in properties:
            return False
        return not self._wizard_wants_to_create_certificate(item_key, properties)

    def _wizard_is_paired(self, item_key, properties) -> bool:
        server = self._get_gamestream_server_from_scanner_settings(properties)
        server.connect()
        return server.is_paired()

    def _wizard_is_not_paired(self, item_key, properties) -> bool:
        return not self._wizard_is_paired(item_key, properties)

    def _wizard_creating_new_connection(self, item_key, properties) -> bool:
        return properties["selected_connection"] == "NONE"

    # after wizard slide actions
    def _wizard_generate_pair_pincode(self, input, item_key, properties):
        gs = self._get_gamestream_server_from_scanner_settings(properties)
        return gs.generatePincode()

    def _wizard_start_pairing_with_server(self, input, item_key, properties):
        logging.info('Starting pairing process')
        pincode = properties[item_key]
        server = self._get_gamestream_server_from_scanner_settings(properties)
        server.connect()

        progress_dialog = kodi.ProgressDialog()
        progress_dialog.startProgress("Starting pairing process")
        paired = server.pairServer(pincode, progress_dialog)
        self.scanner_settings['ispaired'] = paired
        logging.info(f"Finished pairing. Result paired: {paired}")
        progress_dialog.endProgress()
        
        return pincode

    def _wizard_create_certificates(self, input, item_key, properties):
        parent_path = io.FileName(input)
        cert_path = parent_path.pjoin(f"{properties['connection_name']}.crt")
        cert_key_path = parent_path.pjoin(f"{properties['connection_name']}.key")
        properties[item_key] = [
            cert_path.getPath(),
            cert_key_path.getPath()
        ]
        gs = self._get_gamestream_server_from_scanner_settings(properties) 
        if not gs.create_certificates(properties['cert_action']):
            kodi.notify_error("Failed to create certificates for pairing with Gamestream PC")
        return input

    def _wizard_validate_certificates(self, input, item_key, properties):
        properties[item_key] = input
        gs = self._get_gamestream_server_from_scanner_settings(properties) 
        if not gs.validate_certificates():
            kodi.notify_warn(
                'Could not find certificates to validate. Make sure you already paired with '
                'the server with the Shield or Moonlight applications.')

        return input
    
    def _wizard_validate_gamestream_server_connection(self, input, item_key, properties):
        properties[item_key] = input
        gs = self._get_gamestream_server_from_scanner_settings(properties) 
        if not gs.connect():
            kodi.notify_warn('Could not connect to gamestream server')
            return input

        properties['server_id'] = 1 # not yet known what the origin is
        properties['server_uuid'] = gs.get_uniqueid()
        properties['connection_name'] = gs.get_hostname()
        properties['unique_id'] = gs.get_client_id()

        server_uuid = properties['server_uuid']
        host_name = properties['connection_name']
        logging.debug(f'Found correct gamestream server with id "{server_uuid}" and hostname "{host_name}"')

        return input
    
    def _wizard_generate_connection_uid(self, input, item_key, properties):
        gs = self._get_gamestream_server_from_scanner_settings(properties)
        input = gs.get_client_id()
        return input

    def _wizard_get_available_connections(self) -> dict:
        connection_files = GameStreamServer.get_connection_info_files()
        options = collections.OrderedDict()
        options["NONE"] = "Configure new connection"
        for file, name in connection_files.items():
            options[file] = name
        return options

    # Edit settings
    def _configure_get_edit_options(self) -> dict:
        options = collections.OrderedDict()
        options[self._change_name]          = f"Change connection name: '{self.scanner_settings['name']}'"
        options[self._change_server_host]   = f"Change host: '{self.scanner_settings['host']}'"
        options[self._change_client_uid]    = f"Change client ID: '{self.scanner_settings['unique_id']}'"
        options[self._change_certificates]  = f"Change certificates"
        options[self._update_server_info]   = "Update server info"
        
        return options
    
    def _change_name(self):
        server_name = kodi.dialog_keyboard('Edit connection name', self.scanner_settings["name"])
        if server_name is None:
            return
        self.scanner_settings['name'] = server_name

    def _change_server_host(self):
        server_host = kodi.dialog_ipaddr('Edit Gamestream Host', self.scanner_settings['host'])
        if server_host is None:
            return
        self.scanner_settings['host'] = server_host
    
    def _change_client_uid(self):
        uid = kodi.dialog_numeric('Edit Client ID', self.scanner_settings["unique_id"])
        if uid is None:
            return
        self.scanner_settings['unique_id'] = uid
        
    def _change_certificates(self):

        dialog = kodi.ListDialog()
        selected_idx = dialog.select("Change certificates",[
            f"Certificate file: {self.scanner_settings['cert_file']}",
            f"Certificate key file: {self.scanner_settings['cert_key_file']}"
        ])

        item_key = None
        dialog_title = None
        file_mask = ".crt|.key"
        if selected_idx is None or selected_idx < 0:
            return
        if selected_idx == 0:
            item_key = "cert_file"
            dialog_title = "Select the valid certificate file"
            file_mask = ".crt"
        elif selected_idx == 1:
            item_key = "cert_key_file"
            dialog_title = "Select the valid certificate key file"
            file_mask = ".key"
        
        current_path  = self.scanner_settings[item_key]
        selected_path = kodi.browse(type=1, mask=file_mask, text=dialog_title, 
                                    preselected_path=current_path) 

        if selected_path is None or selected_path == current_path:
            logging.debug('Selected certificate path = NONE')
            self._change_certificates()
            return

        self.scanner_settings[item_key] = selected_path
        self._change_certificates()
    
    def _update_server_info(self):
        if not kodi.dialog_yesno('Are you sure you want to update all server info?'): 
            return
        self._wizard_validate_gamestream_server_connection(self.scanner_settings['host']
        , 'host', self.scanner_settings)
              
    def _get_gamestream_server_from_scanner_settings(self, properties):
        selected_connection = properties['selected_connection'] if 'selected_connection' in properties else None
        if selected_connection and selected_connection != 'NONE':
            connection_file = io.FileName(selected_connection)
            gs = GameStreamServer.load_connection(connection_file)
            return gs

        host_name = properties['connection_name'] if 'connection_name' in properties else 'test'
        host = properties['host'] if 'host' in properties else None

        connection_info = GameStreamServer.create_new_connection_info(host_name, host)
        if "unique_id" in properties:
            connection_info["unique_id"] = properties["unique_id"] 
        
        if "certificates_paths" in properties and host_name != 'test':
            certificate_paths = properties["certificates_paths"]
            for cert_file in certificate_paths:
                cert_filepath = io.FileName(cert_file)
                if cert_filepath.getExt() == '.key':
                    connection_info["cert_key_file"] = cert_file
                if cert_filepath.getExt() == '.crt':
                    connection_info["cert_file"] = cert_file
        if "cert_file" in properties:
            connection_info["cert_file"] = properties["cert_file"]
        if "cert_key_file" in properties:
            connection_info["cert_key_file"] = properties["cert_key_file"]

        gs = GameStreamServer(connection_info)
        return gs

    # ~~~ Scan for new files (*.*) and put them in a list ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def _getCandidates(self, scanner_report: report.Reporter) -> typing.List[ROMCandidateABC]:
        self.progress_dialog.startProgress('Reading Nvidia GameStream server...')
        scanner_report.write('Reading Nvidia GameStream server')
     
        streamServer = self._get_gamestream_server_from_scanner_settings(self.scanner_settings)
        connected = streamServer.connect()

        if not connected:
            kodi.notify_error('Unable to connect to gamestream server')
            return None
        
        self.progress_dialog.updateProgress(50)
        games = streamServer.getApps()
        
        self.progress_dialog.updateProgress(80)
        num_games = len(games)
        scanner_report.write(f'Gamestream scanner found {num_games} games')
        
        self.progress_dialog.endProgress()
        return [*(GameStreamCandidate(g) for g in games)]
    
    # --- Get dead entries -----------------------------------------------------------------
    def _getDeadRoms(self, candidates:typing.List[ROMCandidateABC], roms: typing.List[api.ROMObj]) -> typing.List[api.ROMObj]:
        dead_roms = []
        num_roms = len(roms)
        if num_roms == 0:
            logger.info('Collection is empty. No dead ROM check.')
            return dead_roms
        
        logger.info('Starting dead items scan')
        i = 0
            
        self.progress_dialog.startProgress('Checking for dead ROMs ...', num_roms)
        
        candidate_stream_ids = set(c.get_game_id() for c in candidates)
        for rom in reversed(roms):
            stream_id = rom.get_scanned_data_element('gstreamid')
            logger.info(f'Searching stream ID#{stream_id}')
            self.progress_dialog.updateProgress(i)
            
            if stream_id not in candidate_stream_ids:
                logger.info(f'Not found. Marking as dead: #{stream_id} {rom.get_name()}')
                roms.remove(rom)
                dead_roms.append(rom)
            i += 1
            
        self.progress_dialog.endProgress()
        return dead_roms

    # ~~~ Now go processing item by item ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def _processFoundItems(self, 
                           candidates: typing.List[ROMCandidateABC], 
                           roms:typing.List[api.ROMObj],
                           scanner_report: report.Reporter) -> typing.List[api.ROMObj]:

        num_items = len(candidates)    
        new_roms:typing.List[api.ROMObj] = []

        self.progress_dialog.startProgress('Scanning found items', num_items)
        logger.debug('============================== Processing Gamestream Games ==============================')
        scanner_report.write('Processing games ...')
        num_items_checked = 0
        
        streamIdsAlreadyInCollection = set(rom.get_scanned_data_element('gstreamid') for rom in roms)

        for candidate in sorted(candidates, key=lambda c: c.get_sort_value()):
            
            stream_candidate:GameStreamCandidate = candidate
            streamId = stream_candidate.get_game_id()
            
            logger.debug('Searching {} with #{}'.format(stream_candidate.get_name(), streamId))
            self.progress_dialog.updateProgress(num_items_checked, stream_candidate.get_name())
            
            if streamId in streamIdsAlreadyInCollection:
                logger.debug(f'  ID#{streamId} already in collection. Skipping')
                num_items_checked += 1
                continue
            
            logger.debug('========== Processing GameStream game ==========')
            scanner_report.write('>>> title: {}'.format(stream_candidate.get_name()))
            scanner_report.write('>>> ID: {}'.format(stream_candidate.get_game_id()))
        
            logger.debug('Not found. Item {} is new'.format(stream_candidate.get_name()))

            # ~~~~~ Process new ROM and add to the list ~~~~~
            new_rom = stream_candidate.get_ROM()
            new_roms.append(new_rom)
            
            # ~~~ Check if user pressed the cancel button ~~~
            if self.progress_dialog.isCanceled():
                self.progress_dialog.endProgress()
                kodi.dialog_OK('Stopping ROM scanning. No changes have been made.')
                logger.info('User pressed Cancel button when scanning ROMs. ROM scanning stopped.')
                return None
            
            num_items_checked += 1
           
        self.progress_dialog.endProgress()
        return new_roms