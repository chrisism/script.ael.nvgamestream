#
# Advanced Kodi Launcher: Nvidia gamestream launcher implementation
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
import os
import collections

# -- Kodi packages --
import xbmcgui

# --- AEL packages ---
from ael.utils import kodi, io, text
from ael.launchers import LauncherABC

# Local modules
from gamestream import GameStreamServer
import crypto

logger = logging.getLogger(__name__)

# -------------------------------------------------------------------------------------------------
# Launcher to use with a Nvidia Gamestream server connection.
# -------------------------------------------------------------------------------------------------
class NvidiaGameStreamLauncher(LauncherABC):

    # --------------------------------------------------------------------------------------------
    # Core methods
    # --------------------------------------------------------------------------------------------
    def get_name(self) -> str: return 'Nivida GameStream Launcher'
     
    def get_launcher_addon_id(self) -> str: 
        addon_id = kodi.get_addon_id()
        return addon_id

    def get_certificates_path(self): 
        if not 'certificates_path' in self.launcher_settings: return None
        path = self.launcher_settings['certificates_path']
        if path == '': return None
        return io.FileName(path)

    def get_server_id(self): return self.launcher_settings['server_id'] if 'server_id' in self.launcher_settings else 0
    
    # --------------------------------------------------------------------------------------------
    # Launcher build wizard methods
    # --------------------------------------------------------------------------------------------
    #
    # Creates a new launcher using a wizard of dialogs. Called by parent build() method.
    #
    def _builder_get_wizard(self, wizard):    
          #UTILS_OPENSSL_AVAILABLE
        logger.debug('NvidiaGameStreamLauncher::_builder_get_wizard() SSL: "{0}"'.format(crypto.UTILS_OPENSSL_AVAILABLE))
        logger.debug('NvidiaGameStreamLauncher::_builder_get_wizard() Crypto: "{0}"'.format(crypto.UTILS_CRYPTOGRAPHY_AVAILABLE))
        logger.debug('NvidiaGameStreamLauncher::_builder_get_wizard() PyCrypto: "{0}"'.format(crypto.UTILS_PYCRYPTO_AVAILABLE))
        
        info_txt  = 'To pair with your Geforce Experience Computer we need to make use of valid certificates. '
        info_txt += 'Unfortunately at this moment we cannot create these certificates directly from within Kodi.'
        info_txt += 'Please read the wiki for details how to create them before you go further.'

        wizard = kodi.WizardDialog_FormattedMessage(wizard, 'certificates_path', 'Pairing with Gamestream PC',
            info_txt)
        wizard = kodi.WizardDialog_DictionarySelection(wizard, 'application', 'Select the client',
            {'NVIDIA': 'Nvidia', 'MOONLIGHT': 'Moonlight'}, 
            self._builder_check_if_selected_gamestream_client_exists, lambda pk, p: io.is_android())
        wizard = kodi.WizardDialog_DictionarySelection(wizard, 'application', 'Select the client',
            {'JAVA': 'Moonlight-PC (java)', 'EXE': 'Moonlight-Chrome (not supported yet)'},
            None, lambda pk,p: not io.is_android())
        wizard = kodi.WizardDialog_FileBrowse(wizard, 'application', 'Select the Gamestream client jar',
            1, self._builder_get_appbrowser_filter, None, lambda pk, p: not io.is_android())
        wizard = kodi.WizardDialog_Keyboard(wizard, 'args', 'Additional arguments', 
            None, lambda pk, p: not io.is_android())
        wizard = kodi.WizardDialog_Input(wizard, 'server', 'Gamestream Server',
            xbmcgui.INPUT_IPADDRESS, self._builder_validate_gamestream_server_connection)
        # Pairing with pin code will be postponed untill crypto and certificate support in kodi
        # wizard = WizardDialog_Dummy(wizard, 'pincode', None, _builder_generatePairPinCode)
        wizard = kodi.WizardDialog_Dummy(wizard, 'certificates_path', None,
            self._builder_try_to_resolve_path_to_nvidia_certificates)
        wizard = kodi.WizardDialog_FileBrowse(wizard, 'certificates_path', 'Select the path with valid certificates', 
            0, '', self._builder_validate_nvidia_certificates) 
        
        return wizard
    
    def _builder_generatePairPinCode(self, input, item_key, launcher):
        return GameStreamServer(None, None).generatePincode()

    def _builder_check_if_selected_gamestream_client_exists(self, input, item_key, launcher):
        if input == 'NVIDIA':
            nvidiaDataFolder = io.FileName('/data/data/com.nvidia.tegrazone3/', isdir = True)
            nvidiaAppFolder = io.FileName('/storage/emulated/0/Android/data/com.nvidia.tegrazone3/')
            if not nvidiaAppFolder.exists() and not nvidiaDataFolder.exists():
                kodi.notify_warn("Could not find Nvidia Gamestream client. Make sure it's installed.")

        elif input == 'MOONLIGHT':
            moonlightDataFolder = io.FileName('/data/data/com.limelight/', isdir = True)
            moonlightAppFolder = io.FileName('/storage/emulated/0/Android/data/com.limelight/')
            if not moonlightAppFolder.exists() and not moonlightDataFolder.exists():
                kodi.notify_warn("Could not find Moonlight Gamestream client. Make sure it's installed.")

        return input

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
       
    def _builder_get_edit_options(self) -> dict:
        streamClient = self.launcher_settings['application']
        if streamClient == 'NVIDIA':
            streamClient = 'Nvidia'
        elif streamClient == 'MOONLIGHT':
            streamClient = 'Moonlight'

        options = collections.OrderedDict()
        options[self._change_application]   = "Change Application: '{0}'".format(streamClient)
        options[self._change_server_id]     = "Change server ID: '{}'".format(self.get_server_id())
        options[self._change_server_host]   = "Change host: '{}'".format(self.launcher_settings['server'])
        options[self._change_certificates]  = "Change certificates: '{}'".format(self.get_certificates_path().getPath())
        options[self._update_server_info]   = "Update server info"
        return options
    
    def _change_application(self):
        current_application = self.launcher_settings['application']
        
        if io.is_android():            
            options = {'NVIDIA': 'Nvidia', 'MOONLIGHT': 'Moonlight'}  
        else:
            options = {'JAVA': 'Moonlight-PC (java)', 'EXE': 'Moonlight-Chrome (not supported yet)'}

        dialog = kodi.OrdDictionaryDialog()    
        selected_application = dialog.select('Select the client', options)
            
        if io.is_android() and not self._builder_check_if_selected_gamestream_client_exists(selected_application, None, None):
            return False

        if not io.is_android() and selected_application == 'JAVA':
            selected_application = xbmcgui.Dialog().browse(1, 'Select the Gamestream client jar', 'files',
                                                      self._builder_get_appbrowser_filter('application', self.launcher_settings),
                                                      False, False, current_application)

        if selected_application is None or selected_application == current_application:
            return False

        self.launcher_settings['application'] = selected_application
    
    def _change_server_id(self):
        server_id = kodi.dialog_numeric('Edit Server ID', self.get_server_id())
        if server_id is None: return
        self.launcher_settings['server_id'] = server_id
    
    def _change_server_host(self):
        server_host = kodi.dialog_ipaddr('Edit Gamestream Host', self.launcher_settings['server'])
        if server_host is None: return
        self.launcher_settings['server_hostname'] = server_host
        
    def _change_certificates(self):
        current_path  = self.get_certificates_path().getPath()
        selected_path = kodi.browse(type=0, text='Select the path with valid certificates', preselected_path=current_path) 
        if selected_path is None or selected_path == current_path:
            logger.debug('_change_certificates(): Selected path = NONE')
            return

        validated_path = self._builder_validate_nvidia_certificates(selected_path, 'certificates_path', self.launcher_settings)
        self.launcher_settings['certificates_path'] = validated_path

    def _update_server_info(self):
        if not kodi.dialog_yesno('Are you sure you want to update all server info?'): return
        self._builder_validate_gamestream_server_connection(self.launcher_settings['server'],'server', self.launcher_settings)
      
    # ---------------------------------------------------------------------------------------------
    # Execution methods
    # ---------------------------------------------------------------------------------------------
    def get_application(self) -> str:
        stream_client = self.launcher_settings['application']
        
        # java application selected (moonlight-pc)
        if '.jar' in stream_client:
            application = io.FileName(os.getenv("JAVA_HOME"))
            if io.is_windows():
                self.application = application.pjoin('bin\\java.exe')
            else:
                self.application = application.pjoin('bin/java')
            
            return application.getPath()
            
        if io.is_windows():
            app = io.FileName(stream_client)
            application = app.getPath()
            return application
            
        if io.is_android():
            application = '/system/bin/am'
            return application
        
        return stream_client
        
    def get_arguments(self) -> str:
        stream_client = self.launcher_settings['application']
        
        arguments = ''
         # java application selected (moonlight-pc)
        if '.jar' in stream_client:
            arguments =  '-jar "$application$" '
            arguments += '-host $server$ '
            arguments += '-fs '
            arguments += '-app "$gamestream_name$" '
            return True
   
        elif io.is_android():
            if stream_client == 'NVIDIA':
                arguments =  'start --user 0 -a android.intent.action.VIEW '
                arguments += '-n com.nvidia.tegrazone3/com.nvidia.grid.UnifiedLaunchActivity '
                arguments += '-d nvidia://stream/target/$server_id$/$gstreamid$'

            elif stream_client == 'MOONLIGHT':
                arguments =  'start --user 0 -a android.intent.action.MAIN '
                arguments += '-c android.intent.category.LAUNCHER ' 
                arguments += '-n com.limelight/com.limelight.ShortcutTrampoline '
                arguments += '-e Host $server$ '
                arguments += '-e AppId $gstreamid$ '
                arguments += '-e AppName "$gamestream_name$" '
                arguments += '-e PcName "$server_hostname$" '
                arguments += '-e UUID $server_uuid$ '
                arguments += '-e UniqueId {} '.format(text.misc_generate_random_SID())       
        
        original_arguments = self.launcher_settings['args'] if 'args' in self.launcher_settings else ''
        self.launcher_settings['args'] = '{} {}'.format(arguments, original_arguments)
        return super(NvidiaGameStreamLauncher, self).get_arguments()
    
