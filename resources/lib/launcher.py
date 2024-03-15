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
from resources.lib import crypto, helpers


# -------------------------------------------------------------------------------------------------
# Launcher to use with a Nvidia Gamestream server connection.
# -------------------------------------------------------------------------------------------------
class NvidiaGameStreamLauncher(LauncherABC):

    # --------------------------------------------------------------------------------------------
    # Core methods
    # --------------------------------------------------------------------------------------------
    def get_name(self) -> str:
        return 'Nivida GameStream Launcher'
     
    def get_launcher_addon_id(self) -> str:
        addon_id = kodi.get_addon_id()
        return addon_id

    def get_server_id(self):
        return self.launcher_settings['server_id'] if 'server_id' in self.launcher_settings else 0
    
    def load_settings(self):
        super().load_settings()
        if "selected_connection" in self.launcher_settings \
            and self.launcher_settings["selected_connection"]:
            connection_info_file = io.FileName(self.launcher_settings["selected_connection"])
            logging.info(f"Loading settings from {connection_info_file.getPath()}")
            self.connection_info = connection_info_file.readJson()
            self.launcher_settings.update(self.connection_info)

    # --------------------------------------------------------------------------------------------
    # Launcher build wizard methods
    # --------------------------------------------------------------------------------------------
    #
    # Creates a new launcher using a wizard of dialogs. Called by parent build() method.
    #
    def _builder_get_wizard(self, wizard):    
        logging.debug(f'Has Crypto: "{crypto.UTILS_CRYPTOGRAPHY_AVAILABLE}"')
        logging.debug(f'Has PyCrypto: "{crypto.UTILS_PYCRYPTO_AVAILABLE}"')
        logging.debug(f'Has OpenSSL: "{crypto.UTILS_OPENSSL_AVAILABLE}"')
     
        info_txt = ('To pair with your Gamestream Computer we need to make use of valid certificates.\n'
                    'Depending on OS and libraries we might not be able to create certificates directly from within Kodi. '
                    'You can always create them manually with external tools/websites.\n'
                    'Please read the documentation or wiki for details how to create them if needed.')

        options = {}
        options['IMPORT'] = 'Import existing (or create manually)'
        options[crypto.CREATE_WITH_CRYPTOLIB] = f'Use cryptography library (Available: {"yes" if crypto.UTILS_CRYPTOGRAPHY_AVAILABLE else "no"})'
        options[crypto.CREATE_WITH_PYOPENSSL] = f'Use OpenSSL library (Available: {"yes" if crypto.UTILS_OPENSSL_AVAILABLE else "no"}, DEPRECATED)'
        options[crypto.CREATE_WITH_OPENSSL] = 'Execute OpenSSL command'

        wizard = kodi.WizardDialog_DictionarySelection(wizard, 'selected_connection',
                                                       'Select configured connection',
                                                       self._wizard_get_available_connections())

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
                                              0, '', 'files', self._wizard_create_certificates,
                                              self._wizard_wants_to_create_certificate)
        wizard = helpers.WizardDialog_FileBrowseMultiple(wizard, 'certificates_paths', 'Select certificate files',
                                                         1, '', 'files', self._wizard_validate_certificates,
                                                         self._wizard_wants_to_import_certificate)

        # if needed to be paired  
        pair_txt =  'We are going to connect with the Gamestream PC.\n'
        pair_txt += 'On your Gamestream PC, once requested, insert the following PIN code: [B]{}[/B].\n'
        pair_txt += 'Press OK to start pairing process.'
        wizard = kodi.WizardDialog_FormattedMessage(wizard, 'pincode', 'Pairing with Gamestream PC',
                                                    pair_txt, self._wizard_start_pairing_with_server, self._wizard_is_not_paired)
        
        pair_success_txt = 'Plugin is successfully paired with the Gamestream PC.\n'
        pair_success_txt += 'You now can scan/launch games with this connection.'
        wizard = kodi.WizardDialog_FormattedMessage(wizard, 'ispaired', 'Pairing with Gamestream PC',
                                                    pair_success_txt, None, self._wizard_is_paired)

        pair_fail_txt = 'Unfortunately we were not able to pair with the Gamestream PC.\n'
        pair_fail_txt += 'Inspect the logs for more details.'
        wizard = kodi.WizardDialog_FormattedMessage(wizard, 'ispaired', 'Pairing with Gamestream PC',
                                                    pair_fail_txt, None, self._wizard_is_not_paired)
       
        # APP
        wizard = kodi.WizardDialog_DictionarySelection(wizard, 'application', 'Select the client',
                                                       {'NVIDIA': 'Nvidia', 'MOONLIGHT': 'Moonlight'},
                                                       self._wizard_check_if_selected_gamestream_client_exists,
                                                       lambda pk, p: io.is_android())
        wizard = kodi.WizardDialog_DictionarySelection(wizard, 'application', 'Select the client',
                                                       {'JAVA': 'Moonlight-PC (java)',
                                                        'EXE': 'Moonlight-Chrome (not supported yet)'},
                                                       None, lambda pk, p: not io.is_android())
        wizard = kodi.WizardDialog_FileBrowse(wizard, 'application', 'Select the Gamestream client jar',
                                              1, self._builder_get_appbrowser_filter, None, None, lambda pk, p: not io.is_android())
        wizard = kodi.WizardDialog_Keyboard(wizard, 'args', 'Additional arguments',
                                            None, lambda pk, p: not io.is_android())
        
        return wizard
        
    def _build_post_wizard_hook(self):
        if self.launcher_settings["selected_connection"] == "NONE":
            gs = self._get_gamestream_server_from_launcher_settings(self.launcher_settings)
            connection_path = gs.store_connection_info()
            self.launcher_settings["selected_connection"] = connection_path
        else:
            connection_info_file = io.FileName(self.launcher_settings["selected_connection"])
            gs = GameStreamServer.load_connection(connection_info_file)
            gs.update_connection_info(self.launcher_settings)
            connection_path = gs.store_connection_info()
        
        self.launcher_settings.pop("ispaired", None)
        self.launcher_settings.pop("pincode", None)
        self.launcher_settings.pop("dummy", None)
        self.launcher_settings.pop("certificates_paths", None)
        self.launcher_settings.pop("cert_action", None)
        self.launcher_settings.pop("server_uuid", None)
        self.launcher_settings.pop("server_name", None)
        self.launcher_settings.pop("host", None)
        self.launcher_settings.pop("connection_name", None)
        self.launcher_settings.pop("unique_id", None)
        self.launcher_settings.pop("cert_file", None)
        self.launcher_settings.pop("cert_key_file", None)
       
        return True

    # wizard slide conditions
    def _wizard_wants_to_create_certificate(self, item_key, properties) -> bool:
        if 'cert_action' not in properties:
            return False

        return properties['cert_action'] in [
            crypto.CREATE_WITH_CRYPTOLIB,
            crypto.CREATE_WITH_PYOPENSSL,
            crypto.CREATE_WITH_OPENSSL]

    def _wizard_wants_to_import_certificate(self, item_key, properties) -> bool:
        if 'cert_action' not in properties:
            return False
        return not self._wizard_wants_to_create_certificate(item_key, properties)

    def _wizard_is_paired(self, item_key, properties) -> bool:
        server = self._get_gamestream_server_from_launcher_settings(properties)
        server.connect()
        return server.is_paired()

    def _wizard_is_not_paired(self, item_key, properties) -> bool:
        return not self._wizard_is_paired(item_key, properties)

    def _wizard_creating_new_connection(self, item_key, properties) -> bool:
        return properties["selected_connection"] == "NONE"

    # after wizard slide actions
    def _wizard_generate_pair_pincode(self, input, item_key, properties):
        gs = self._get_gamestream_server_from_launcher_settings(properties)
        return gs.generatePincode()

    def _wizard_start_pairing_with_server(self, input, item_key, properties):
        logging.info('Starting pairing process')
        pincode = properties[item_key]
        server = self._get_gamestream_server_from_launcher_settings(properties)
        server.connect()

        progress_dialog = kodi.ProgressDialog()
        progress_dialog.startProgress("Starting pairing process")
        paired = server.pairServer(pincode, progress_dialog)
        self.launcher_settings['ispaired'] = paired
        logging.info(f"Finished pairing. Result paired: {paired}")
        progress_dialog.endProgress()
        
        return pincode

    def _wizard_check_if_selected_gamestream_client_exists(self, input, item_key, launcher):
        if input == 'NVIDIA':
            nvidiaDataFolder = io.FileName('/data/data/com.nvidia.tegrazone3/', isdir=True)
            nvidiaAppFolder = io.FileName('/storage/emulated/0/Android/data/com.nvidia.tegrazone3/')
            if not nvidiaAppFolder.exists() and not nvidiaDataFolder.exists():
                kodi.notify_warn("Could not find Nvidia Gamestream client. Make sure it's installed.")

        elif input == 'MOONLIGHT':
            moonlightDataFolder = io.FileName('/data/data/com.limelight/', isdir=True)
            moonlightAppFolder = io.FileName('/storage/emulated/0/Android/data/com.limelight/')
            if not moonlightAppFolder.exists() and not moonlightDataFolder.exists():
                kodi.notify_warn("Could not find Moonlight Gamestream client. Make sure it's installed.")

        return input

    def _wizard_create_certificates(self, input, item_key, properties):
        parent_path = io.FileName(input)
        cert_path = parent_path.pjoin(f"{properties['connection_name']}.crt")
        cert_key_path = parent_path.pjoin(f"{properties['connection_name']}.key")
        properties[item_key] = [
            cert_path.getPath(),
            cert_key_path.getPath()
        ]
        gs = self._get_gamestream_server_from_launcher_settings(properties)
        if not gs.create_certificates(properties['cert_action']):
            kodi.notify_error("Failed to create certificates for pairing with Gamestream PC")
        return input

    def _wizard_validate_certificates(self, input, item_key, properties):
        properties[item_key] = input
        gs = self._get_gamestream_server_from_launcher_settings(properties)
        if not gs.validate_certificates():
            kodi.notify_warn(
                'Could not find certificates to validate. Make sure you already paired with '
                'the server with the Shield or Moonlight applications.')

        return input
    
    def _wizard_validate_gamestream_server_connection(self, input, item_key, properties):
        properties[item_key] = input
        gs = self._get_gamestream_server_from_launcher_settings(properties)
        if not gs.connect():
            kodi.notify_warn('Could not connect to gamestream server')
            return input

        properties['server_id'] = 1  # not yet known what the origin is
        properties['server_uuid'] = gs.get_uniqueid()
        properties['server_name'] = gs.get_hostname()
        properties['connection_name'] = gs.get_hostname()
        properties['unique_id'] = gs.get_client_id()

        server_uuid = properties['server_uuid']
        host_name = properties['connection_name']
        logging.debug(f'Found correct gamestream server with id "{server_uuid}" and hostname "{host_name}"')

        return input
    
    def _wizard_generate_connection_uid(self, input, item_key, properties):
        gs = self._get_gamestream_server_from_launcher_settings(properties)
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
    def _builder_get_edit_options(self) -> dict:
        options = super()._builder_get_edit_options()
        
        streamClient = self.launcher_settings['application']
        if streamClient == 'NVIDIA':
            streamClient = 'Nvidia'
        elif streamClient == 'MOONLIGHT':
            streamClient = 'Moonlight'

        options[self._change_application] = f"Change Application: '{streamClient}'"
        if streamClient == 'NVIDIA':
            options[self._change_server_id] = f"Change server ID: '{self.get_server_id()}'"
        options[self._change_server_host] = f"Change host: '{self.launcher_settings['host']}'"
        options[self._change_client_uid] = f"Change client ID: '{self.launcher_settings['unique_id']}'"
        options[self._change_certificates] = "Change certificates"
        options[self._update_server_info] = "Update server info"
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
        if server_id is None:
            return
        self.launcher_settings['server_id'] = server_id
    
    def _change_server_host(self):
        server_host = kodi.dialog_ipaddr('Edit Gamestream Host', self.launcher_settings['host'])
        if server_host is None:
            return
        self.launcher_settings['host'] = server_host
    
    def _change_client_uid(self):
        uid = kodi.dialog_numeric('Edit Client ID', self.launcher_settings["unique_id"])
        if uid is None:
            return
        self.launcher_settings['unique_id'] = uid
        
    def _change_certificates(self):
        dialog = kodi.ListDialog()
        selected_idx = dialog.select("Change certificates", [
            f"Certificate file: {self.launcher_settings['cert_file']}",
            f"Certificate key file: {self.launcher_settings['cert_key_file']}"
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
        
        current_path = self.launcher_settings[item_key]
        selected_path = kodi.browse(type=1, mask=file_mask, text=dialog_title,
                                    preselected_path=current_path)

        if selected_path is None or selected_path == current_path:
            logging.debug('Selected certificate path = NONE')
            self._change_certificates()
            return

        self.launcher_settings[item_key] = selected_path
        self._change_certificates()

    def _update_server_info(self):
        if not kodi.dialog_yesno('Are you sure you want to update all server info?'):
            return
        self._wizard_validate_gamestream_server_connection(self.launcher_settings['host'],
                                                           'host', self.launcher_settings)
      
    def _get_gamestream_server_from_launcher_settings(self, properties):
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
        if "server_name" in properties:
            connection_info["server_name"] = properties["server_name"]

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
            arguments.append('-host $host$')
            arguments.append('-fs')
            arguments.append('-app "$gamestream_name$"')

        if io.is_android():
            if stream_client == "NVIDIA":
                server_id = self.get_server_id()
                kwargs["intent"] = "android.intent.action.VIEW"
                kwargs["category"] = "android.intent.category.DEFAULT"
                kwargs["dataURI"] = f"nvidia://stream/target/{server_id}/$gstreamid$"
                kwargs["flags"] = "270532608"  # FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_RESET_TASK_IF_NEEDED
                kwargs["className"] = "com.nvidia.gsPlayer.UnifiedLaunchActivity"

            elif stream_client == "MOONLIGHT":
                kwargs["intent"] = "android.intent.action.MAIN"
                kwargs["category"] = "android.intent.category.DEFAULT"  # .LAUNCHER"
                kwargs["flags"] = "270532608"  # FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_RESET_TASK_IF_NEEDED
                kwargs["className"] = "com.limelight.ShortcutTrampoline"
            
                arguments.append('Host $host$')
                arguments.append('AppId $gstreamid$')
                arguments.append('AppName $gamestream_name$')
                arguments.append('PcName $server_name$')
                arguments.append('UUID $server_uuid$')
                arguments.append(f'UniqueId {text.misc_generate_random_SID()}')

        return super(NvidiaGameStreamLauncher, self).get_arguments(*arguments, **kwargs)
