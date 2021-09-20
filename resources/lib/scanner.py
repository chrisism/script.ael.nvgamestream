# -*- coding: utf-8 -*-
#
# Advanced Emulator Launcher: Nvidia gamestream scanner implementation
#
# Copyright (c) 2016-2018 Wintermute0110 <wintermute0110@gmail.com>
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

# --- AEL packages ---
from ael import report, api
from ael.utils import kodi, io

from ael.scanners import RomScannerStrategy, ROMCandidateABC

# Local modules
from gamestream import GameStreamServer
import crypto

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
          #UTILS_OPENSSL_AVAILABLE
        logger.debug('NvidiaStreamScanner::_configure_get_wizard() SSL: "{0}"'.format(crypto.UTILS_OPENSSL_AVAILABLE))
        logger.debug('NvidiaStreamScanner::_configure_get_wizard() Crypto: "{0}"'.format(crypto.UTILS_CRYPTOGRAPHY_AVAILABLE))
        logger.debug('NvidiaStreamScanner::_configure_get_wizard() PyCrypto: "{0}"'.format(crypto.UTILS_PYCRYPTO_AVAILABLE))
        
        info_txt  = 'To pair with your Geforce Experience Computer we need to make use of valid certificates. '
        info_txt += 'Unfortunately at this moment we cannot create these certificates directly from within Kodi.'
        info_txt += 'Please read the wiki for details how to create them before you go further.'

        wizard = kodi.WizardDialog_FormattedMessage(wizard, 'certificates_path', 'Pairing with Gamestream PC',
            info_txt)
        wizard = kodi.WizardDialog_Input(wizard, 'server', 'Gamestream Server',
            xbmcgui.INPUT_IPADDRESS, self._builder_validate_gamestream_server_connection)
        # Pairing with pin code will be postponed untill crypto and certificate support in kodi
        # wizard = WizardDialog_Dummy(wizard, 'pincode', None, _builder_generatePairPinCode)
        wizard = kodi.WizardDialog_Dummy(wizard, 'certificates_path', None,
            self._builder_try_to_resolve_path_to_nvidia_certificates)
        wizard = kodi.WizardDialog_FileBrowse(wizard, 'certificates_path', 'Select the path with valid certificates', 
            0, '', self._builder_validate_nvidia_certificates) 
        
        return wizard
      
    def _configure_post_wizard_hook(self):
        return True
    
    def _builder_try_to_resolve_path_to_nvidia_certificates(self, input, item_key, launcher):
        path = GameStreamServer.try_to_resolve_path_to_nvidia_certificates()
        return path

    def _builder_validate_nvidia_certificates(self, input, item_key, launcher):
        certificates_path = io.FileName(input)
        gs = GameStreamServer(input, certificates_path)
        if not gs.validate_certificates():
            kodi.notify_warn(
                'Could not find certificates to validate. Make sure you already paired with '
                'the server with the Shield or Moonlight applications.')

        return certificates_path.getPath()
    
    def _builder_validate_gamestream_server_connection(self, input, item_key, launcher):
        gs = GameStreamServer(input, None)
        if not gs.connect():
            kodi.notify_warn('Could not connect to gamestream server')
            return input

        launcher['server_id'] = 4 # not yet known what the origin is
        launcher['server_uuid'] = gs.get_uniqueid()
        launcher['server_hostname'] = gs.get_hostname()

        logger.debug('validate_gamestream_server_connection() Found correct gamestream server with id "{}" and hostname "{}"'.format(launcher['server_uuid'],launcher['server_hostname']))

        return input
    
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

        validated_path = self._builder_validate_nvidia_certificates(selected_path, 'certificates_path', self.scanner_settings)
        self.scanner_settings['certificates_path'] = validated_path

    def _update_server_info(self):
        if not kodi.dialog_yesno('Are you sure you want to update all server info?'): return
        self._builder_validate_gamestream_server_connection(self.scanner_settings['server'],'server', self.scanner_settings)
            
    # ~~~ Scan for new files (*.*) and put them in a list ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def _getCandidates(self, launcher_report: report.Reporter) -> typing.List[ROMCandidateABC]:
        self.progress_dialog.startProgress('Reading Nvidia GameStream server...')
        launcher_report.write('Reading Nvidia GameStream server')
     
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
        launcher_report.write('Gamestream scanner found {} games'.format(num_games))
        
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
                           launcher_report: report.Reporter) -> typing.List[api.ROMObj]:

        num_items = len(candidates)    
        new_roms:typing.List[api.ROMObj] = []

        self.progress_dialog.startProgress('Scanning found items', num_items)
        logger.debug('============================== Processing Gamestream Games ==============================')
        launcher_report.write('Processing games ...')
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
            launcher_report.write('>>> title: {}'.format(stream_candidate.get_name()))
            launcher_report.write('>>> ID: {}'.format(stream_candidate.get_game_id()))
        
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

             