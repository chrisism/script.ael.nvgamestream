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
import typing

# -- Kodi packages --
import xbmcgui

# --- AKL packages ---
from akl.utils import kodi, io, text
from akl.launchers import LauncherABC

# Local modules
from resources.lib.gamestream import GameStreamServer
from resources.lib import crypto

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
        logger.debug(f'NvidiaStreamScanner::_builder_get_wizard() Crypto: "{crypto.UTILS_CRYPTOGRAPHY_AVAILABLE}"')
        logger.debug(f'NvidiaStreamScanner::_builder_get_wizard() PyCrypto: "{crypto.UTILS_PYCRYPTO_AVAILABLE}"')
        logger.debug(f'NvidiaStreamScanner::_builder_get_wizard() OpenSSL: "{crypto.UTILS_OPENSSL_AVAILABLE}"')
     
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

        # APP
        wizard = kodi.WizardDialog_DictionarySelection(wizard, 'application', 'Select the client',
            {'NVIDIA': 'Nvidia', 'MOONLIGHT': 'Moonlight'}, 
            self._wizard_check_if_selected_gamestream_client_exists, lambda pk, p: io.is_android())
        wizard = kodi.WizardDialog_DictionarySelection(wizard, 'application', 'Select the client',
            {'JAVA': 'Moonlight-PC (java)', 'EXE': 'Moonlight-Chrome (not supported yet)'},
            None, lambda pk,p: not io.is_android())
        wizard = kodi.WizardDialog_FileBrowse(wizard, 'application', 'Select the Gamestream client jar',
            1, self._builder_get_appbrowser_filter, None, lambda pk, p: not io.is_android())
        wizard = kodi.WizardDialog_Keyboard(wizard, 'args', 'Additional arguments', 
            None, lambda pk, p: not io.is_android())

        # CONNECTION
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
    def _wizard_generate_pair_pincode(self, input, item_key, launcher):
        return GameStreamServer(None, None).generatePincode()

    def _wizard_start_pairing_with_server(self, input, item_key, properties):
        logger.info('Starting pairing process')
        certificates_path = io.FileName(properties['certificates_path'])
        pincode = properties[item_key]

        logger.info('Starting pairing process')
        server = GameStreamServer(
            properties['server'], 
            certificates_path)
        server.connect()

        progress_dialog = kodi.ProgressDialog()
        progress_dialog.startProgress("Starting pairing process")
        paired = server.pairServer(pincode, progress_dialog)
        self.launcher_settings['ispaired'] = paired
        logger.info(f"Finished pairing. Result paired: {paired}")
        progress_dialog.endProgress()
        
        return pincode

    def _wizard_check_if_selected_gamestream_client_exists(self, input, item_key, launcher):
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

    def _wizard_try_to_resolve_path_to_nvidia_certificates(self, input, item_key, launcher):
        path = GameStreamServer.try_to_resolve_path_to_nvidia_certificates()
        return path

    def _wizard_create_certificates(self, input, item_key, properties):
        certificates_path = io.FileName(input)
        gs = GameStreamServer(input, certificates_path)
        if not gs.create_certificates(properties['cert_action']):
            kodi.notify_error("Failed to create certificates for pairing with Gamestream PC")
        return input

    def _wizard_validate_nvidia_certificates(self, input, item_key, launcher):
        certificates_path = io.FileName(input)
        gs = GameStreamServer(input, certificates_path)
        if not gs.validate_certificates():
            kodi.notify_warn(
                'Could not find certificates to validate. Make sure you already paired with '
                'the server with the Shield or Moonlight applications.')

        return certificates_path.getPath()
    
    def _wizard_validate_gamestream_server_connection(self, input, item_key, launcher):
        gs = GameStreamServer(input, None, debug_mode=True)
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
        options[self._change_application]   = f"Change Application: '{streamClient}'"
        options[self._change_server_id]     = f"Change server ID: '{self.get_server_id()}'"
        options[self._change_server_host]   = f"Change host: '{self.launcher_settings['server']}'"
        options[self._change_certificates]  = f"Change certificates: '{self.get_certificates_path().getPath()}'"
        options[self._update_server_info]   = "Update server info"
        return options

    def _change_application(self):
        current_application = self.launcher_settings['application']
        
        if io.is_android():            
            options = {
                'NVIDIA': 'Nvidia',
                'MOONLIGHT': 'Moonlight'
            }  
        else:
            options = {
                'JAVA': 'Moonlight-PC (java)', 
                'EXE': 'Moonlight-Chrome (not supported yet)'
            }

        dialog = kodi.OrdDictionaryDialog()    
        selected_application = dialog.select('Select the client', options)
            
        if io.is_android() and not self._wizard_check_if_selected_gamestream_client_exists(selected_application, None, None):
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

        validated_path = self._wizard_validate_nvidia_certificates(selected_path, 'certificates_path', self.launcher_settings)
        self.launcher_settings['certificates_path'] = validated_path

    def _update_server_info(self):
        if not kodi.dialog_yesno('Are you sure you want to update all server info?'): return
        self._wizard_validate_gamestream_server_connection(self.launcher_settings['server'],'server', self.launcher_settings)
      
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
            if stream_client == "NVIDIA":
                application = "com.nvidia.tegrazone3"
            elif stream_client == "MOONLIGHT":
                application = "com.limelight"
            return application
        
        return stream_client

    def get_arguments(self, *args, **kwargs) -> typing.Tuple[list, dict]:
        stream_client = self.launcher_settings['application']
        arguments = list(args)

        # java application selected (moonlight-pc)
        if '.jar' in stream_client:
            arguments.append('-jar "$application$"')
            arguments.append('-host $server$')
            arguments.append('-fs')
            arguments.append('-app "$gamestream_name$"')

        if io.is_android():
            if stream_client == "NVIDIA":
                server_id = self.get_server_id()
                kwargs["intent"]  = "android.intent.action.VIEW"
                kwargs["dataURI"] = f"nvidia://stream/target/{server_id}/$gstreamid$"
                kwargs["flags"] = "270532608" #  FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_RESET_TASK_IF_NEEDED
                kwargs["className"] = "com.nvidia.grid.UnifiedLaunchActivity"
            
            elif stream_client == "MOONLIGHT":
                kwargs["intent"]   = "android.intent.action.MAIN"
                kwargs["category"] = "android.intent.category.LAUNCHER"
                kwargs["flags"] = "270532608" #  FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_RESET_TASK_IF_NEEDED
                kwargs["className"] = "com.limelight.ShortcutTrampoline"
            
                arguments.append('Host $server$')
                arguments.append('AppId $gstreamid$')
                arguments.append('AppName "$gamestream_name$"')
                arguments.append('PcName "$server_hostname$"')
                arguments.append('UUID $server_uuid$')
                arguments.append(f'UniqueId {text.misc_generate_random_SID()}')  

        return super(NvidiaGameStreamLauncher, self).get_arguments(*arguments, **kwargs)
