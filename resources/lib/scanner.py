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

# --- Kodi packages --
import xbmcgui

# --- AKL packages ---
from akl import report, api
from akl.utils import kodi, io

from akl.scanners import RomScannerStrategy, ROMCandidateABC

# Local modules
from resources.lib.gamestream import GameStreamServer
from resources.lib import crypto

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
            'gamestream_name': self.get_name() # so that we always have the original name
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
    
    def get_server(self) -> str:
        return self.scanner_settings['server'] if 'server' in self.scanner_settings else None
      
    def get_certificates_path(self):
        path = self.scanner_settings['certificates_path'] if 'certificates_path' in self.scanner_settings else None
        if path: return io.FileName(path)
        return None

    def _configure_get_wizard(self, wizard) -> kodi.WizardDialog:
        logger.debug(f'NvidiaStreamScanner::_configure_get_wizard() Crypto: "{crypto.UTILS_CRYPTOGRAPHY_AVAILABLE}"')
        logger.debug(f'NvidiaStreamScanner::_configure_get_wizard() PyCrypto: "{crypto.UTILS_PYCRYPTO_AVAILABLE}"')
        logger.debug(f'NvidiaStreamScanner::_configure_get_wizard() OpenSSL: "{crypto.UTILS_OPENSSL_AVAILABLE}"')
     
        info_txt  = 'To pair with your Geforce Experience Computer we need to make use of valid certificates.\n'
        info_txt += 'Depending on OS and libraries we might not be able to create certificates directly from within Kodi. '
        info_txt += 'You can always create them manually with external tools/websites.\n'
        info_txt += 'Please read the documentation or wiki for details how to create them if needed.'

        options = {}
        options['IMPORT'] = 'Import existing (or create manually)'
        options[crypto.CREATE_WITH_CRYPTOLIB] = f'Use cryptography library (Available: {"yes" if crypto.UTILS_CRYPTOGRAPHY_AVAILABLE else "no"})'
        options[crypto.CREATE_WITH_PYOPENSSL] = f'Use OpenSSL library (Available: {"yes" if crypto.UTILS_OPENSSL_AVAILABLE else "no"}, DEPRECATED)'
        options[crypto.CREATE_WITH_OPENSSL]   = f'Execute OpenSSL command'

        wizard = kodi.WizardDialog_Dummy(wizard, 'certificates_path', None,
            self._wizard_try_to_resolve_path_to_nvidia_certificates)
        wizard = kodi.WizardDialog_Dummy(wizard, 'pincode', None, 
            self._wizard_generate_pair_pincode)

        wizard = kodi.WizardDialog_Input(wizard, 'server', 'Gamestream Server',
            xbmcgui.INPUT_IPADDRESS, self._wizard_validate_gamestream_server_connection)
        wizard = kodi.WizardDialog_FormattedMessage(wizard, 'dummy', 'Pairing with Gamestream PC',
            info_txt)        
        wizard = kodi.WizardDialog_DictionarySelection(wizard, 'cert_action', 'How to apply certificates', options)
        wizard = kodi.WizardDialog_FileBrowse(wizard, 'certificates_path', 'Select location to store certificates', 
            0, '', self._wizard_create_certificates, self._wizard_wants_to_create_certificate) 
        wizard = kodi.WizardDialog_FileBrowse(wizard, 'certificates_path', 'Select certificates path', 
            0, '', self._wizard_validate_nvidia_certificates, self._wizard_wants_to_import_certificate) 

        pair_txt =  'We are going to connect with the Gamestream PC.\n'
        pair_txt += 'On your Gamestream PC, once requested, insert the following PIN code: [B]{}[/B].\n'
        pair_txt += 'Press OK to start pairing process.'
        wizard = kodi.WizardDialog_FormattedMessage(wizard, 'pincode', 'Pairing with Gamestream PC',
            pair_txt, self._wizard_start_pairing_with_server, self._wizard_is_not_paired)
        
        pair_success_txt =  'Plugin is successfully paired with the Gamestream PC.\n'
        pair_success_txt += 'You now can scan the game collection.'
        wizard = kodi.WizardDialog_FormattedMessage(wizard, 'ispaired', 'Pairing with Gamestream PC',
            pair_success_txt, None, self._wizard_is_paired)

        pair_fail_txt =  'Unfortunately we were not able to pair with the Gamestream PC.\n'
        pair_fail_txt += 'Inspect the logs for more details.'
        wizard = kodi.WizardDialog_FormattedMessage(wizard, 'ispaired', 'Pairing with Gamestream PC',
            pair_fail_txt, None, self._wizard_is_not_paired)

        return wizard
      
    def _configure_post_wizard_hook(self):
        return True
    
    # wizard slide conditions
    def _wizard_wants_to_create_certificate(self, item_key, properties) -> bool:
        return properties['cert_action'] in [
            crypto.CREATE_WITH_CRYPTOLIB, 
            crypto.CREATE_WITH_PYOPENSSL, 
            crypto.CREATE_WITH_OPENSSL]

    def _wizard_wants_to_import_certificate(self, item_key, properties)  -> bool:
        return not self._wizard_wants_to_create_certificate(item_key, properties)

    def _wizard_is_paired(self, item_key, properties) -> bool:
        certificates_path = io.FileName(properties['certificates_path'])
        server = GameStreamServer(
            properties['server'], 
            certificates_path)

        server.connect()
        return server.is_paired()

    def _wizard_is_not_paired(self, item_key, properties) -> bool:
        return not self._wizard_is_paired(item_key, properties)

    # after wizard slide actions
    def _wizard_try_to_resolve_path_to_nvidia_certificates(self, input, item_key, properties):
        path = GameStreamServer.try_to_resolve_path_to_nvidia_certificates()
        return path

    def _wizard_create_certificates(self, input, item_key, properties):
        certificates_path = io.FileName(input)
        gs = GameStreamServer(input, certificates_path)
        if not gs.create_certificates(properties['cert_action']):
            kodi.notify_error("Failed to create certificates for pairing with Gamestream PC")
        return input

    def _wizard_validate_nvidia_certificates(self, input, item_key, properties):
        certificates_path = io.FileName(input)
        gs = GameStreamServer(input, certificates_path)
        if not gs.validate_certificates():
            kodi.notify_warn(
                'Could not find certificates to validate. Make sure you already paired with '
                'the server with the Shield or Moonlight applications.')

        return certificates_path.getPath()
    
    def _wizard_validate_gamestream_server_connection(self, input, item_key, properties):
        gs = GameStreamServer(input, None)
        if not gs.connect():
            kodi.notify_warn('Could not connect to gamestream server')
            return input

        properties['server_id'] = 4 # not yet known what the origin is
        properties['server_uuid'] = gs.get_uniqueid()
        properties['server_hostname'] = gs.get_hostname()

        logger.debug(f'Found correct gamestream server with id "{properties["server_uuid"]}" and hostname "{properties["server_hostname"]}"')
        return input
    
    def _wizard_generate_pair_pincode(self, input, item_key, properties):
        return GameStreamServer(None, None).generatePincode()

    def _wizard_start_pairing_with_server(self, input, item_key, properties):
        logger.info('Starting pairing process')
        certificates_path = io.FileName(properties['certificates_path'])
        pincode = properties[item_key]

        logger.info('Starting pairing process')
        server = GameStreamServer(
            properties['server'], 
            certificates_path, 
            debug_mode=True)
        server.connect()

        progress_dialog = kodi.ProgressDialog()
        progress_dialog.startProgress()
        paired = server.pairServer(pincode, progress_dialog)
        self.scanner_settings['ispaired'] = paired
        logger.info(f"Finished pairing. Result paired: {paired}")
        progress_dialog.endProgress()
        
        return pincode

    def _configure_get_edit_options(self) -> dict:

        options = collections.OrderedDict()
        options[self._change_server_host]   = "Change host: '{}'".format(self.scanner_settings['server'])
        options[self._change_certificates]  = "Change certificates: '{}'".format(self.get_certificates_path().getPath())
        options[self._update_server_info]   = "Update server info"
        return options
    
    def _change_server_host(self):
        server_host = kodi.dialog_ipaddr('Edit Gamestream Host', self.scanner_settings['server'])
        if server_host is None: return
        self.scanner_settings['server_hostname'] = server_host
        
    def _change_certificates(self):
        current_path  = self.get_certificates_path().getPath()
        selected_path = kodi.browse(type=0, text='Select the path with valid certificates', preselected_path=current_path) 
        if selected_path is None or selected_path == current_path:
            logger.debug('_change_certificates(): Selected path = NONE')
            return

        validated_path = self._wizard_validate_nvidia_certificates(selected_path, 'certificates_path', self.scanner_settings)
        self.scanner_settings['certificates_path'] = validated_path

    def _update_server_info(self):
        if not kodi.dialog_yesno('Are you sure you want to update all server info?'): return
        self._wizard_validate_gamestream_server_connection(self.scanner_settings['server'],'server', self.scanner_settings)
            
    # ~~~ Scan for new files (*.*) and put them in a list ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def _getCandidates(self, scanner_report: report.Reporter) -> typing.List[ROMCandidateABC]:
        self.progress_dialog.startProgress('Reading Nvidia GameStream server...')
        scanner_report.write('Reading Nvidia GameStream server')
     
        server_host         = self.get_server()
        certificates_path   = self.get_certificates_path()
                
        streamServer = GameStreamServer(server_host, certificates_path, False)
        connected = streamServer.connect()

        if not connected:
            kodi.notify_error('Unable to connect to gamestream server')
            return None
        
        self.progress_dialog.updateProgress(50)
        games = streamServer.getApps()
        
        self.progress_dialog.updateProgress(80)
        num_games = len(games)
        scanner_report.write('Gamestream scanner found {} games'.format(num_games))
        
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
        
        streamIds = set(streamableGame['ID'] for streamableGame in candidates)
        candidate_stream_ids = set(c.get_game_id() for c in candidates)
        
        for rom in reversed(roms):
            stream_id = rom.get_scanned_data_element('gstreamid')
            logger.info('Searching stream ID#{}'.format(stream_id))
            self.progress_dialog.updateProgress(i)
            
            if stream_id not in candidate_stream_ids:
                logger.info('Not found. Marking as dead: #{} {}'.format(stream_id, rom.get_name()))
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
                logger.debug('  ID#{} already in collection. Skipping'.format(streamId))
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