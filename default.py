# -*- coding: utf-8 -*-
#
# Nvidia Gamestream plugin for AKL
#
# --- Python standard library ---
from __future__ import unicode_literals
from __future__ import division

import sys
import logging
    
# --- Kodi stuff ---
import xbmcaddon

# AKL main imports
from akl import settings, addons
from akl.utils import kodilogging, io, kodi
from akl.launchers import ExecutionSettings, get_executor_factory

# Local modules
from resources.lib.launcher import NvidiaGameStreamLauncher
from resources.lib.scanner import NvidiaStreamScanner

kodilogging.config()
logger = logging.getLogger(__name__)

# --- Addon object (used to access settings) ---
addon = xbmcaddon.Addon()
addon_id = addon.getAddonInfo('id')
addon_version = addon.getAddonInfo('version')


# ---------------------------------------------------------------------------------------------
# This is the plugin entry point.
# ---------------------------------------------------------------------------------------------
def run_plugin():
    os_name = io.is_which_os()

    # --- Some debug stuff for development ---
    logger.info('------------ Called Advanced Kodi Launcher Plugin: Nvidia Gamestream ------------')
    logger.info(f'addon.id         "{addon_id}"')
    logger.info(f'addon.version    "{addon_version}"')
    logger.info(f'sys.platform     "{sys.platform}"')
    logger.info(f'OS               "{os_name}"')

    for i in range(len(sys.argv)):
        logger.info(f'sys.argv[{i}] "{sys.argv[i]}"')

    parser = addons.AklAddonArguments('script.akl.nvgamestream')
    try:
        parser.parse()
    except Exception as ex:
        logger.error('Exception in plugin', exc_info=ex)
        kodi.dialog_OK(text=parser.get_usage())
        return
    
    if parser.get_command() == addons.AklAddonArguments.LAUNCH:
        launch_rom(parser)
    elif parser.get_command() == addons.AklAddonArguments.CONFIGURE_LAUNCHER:
        configure_launcher(parser)
    elif parser.get_command() == addons.AklAddonArguments.SCAN:
        scan_for_roms(parser)
    elif parser.get_command() == addons.AklAddonArguments.CONFIGURE_SCANNER:
        configure_scanner(parser)
    else:
        kodi.dialog_OK(text=parser.get_help())
    
    logger.debug('Advanced Kodi Launcher Plugin: Nvidia Gamestream -> exit')


# ---------------------------------------------------------------------------------------------
# Launcher methods.
# ---------------------------------------------------------------------------------------------
# Arguments: --akl_addon_id --rom_id
def launch_rom(args: addons.AklAddonArguments):
    logger.debug('Nvidia Gamestream Launcher: Starting ...')
    
    try:
        execution_settings = ExecutionSettings()
        execution_settings.delay_tempo = settings.getSettingAsInt('delay_tempo')
        execution_settings.display_launcher_notify = settings.getSettingAsBool('display_launcher_notify')
        execution_settings.is_non_blocking = settings.getSettingAsBool('is_non_blocking')
        execution_settings.media_state_action = settings.getSettingAsInt('media_state_action')
        execution_settings.suspend_audio_engine = settings.getSettingAsBool('suspend_audio_engine')
        execution_settings.suspend_screensaver = settings.getSettingAsBool('suspend_screensaver')
        execution_settings.suspend_joystick_engine = settings.getSettingAsBool('suspend_joystick')
                
        addon_dir = kodi.getAddonDir()
        report_path = addon_dir.pjoin('reports')
        if not report_path.exists():
            report_path.makedirs()
        report_path = report_path.pjoin(f'{args.get_akl_addon_id()}-{args.get_entity_id()}.txt')
        
        executor_factory = get_executor_factory(report_path)
        launcher = NvidiaGameStreamLauncher(
            args.get_akl_addon_id(),
            args.get_entity_id(),
            args.get_webserver_host(),
            args.get_webserver_port(),
            executor_factory,
            execution_settings)
        
        launcher.launch()
    except Exception as e:
        logger.error('Exception while executing ROM', exc_info=e)
        kodi.notify_error('Failed to execute ROM')


# Arguments: --akl_addon_id --entity_id --entity_type
def configure_launcher(args: addons.AklAddonArguments):
    logger.debug('Nvidia Gamestream Launcher: Configuring ...')
        
    launcher = NvidiaGameStreamLauncher(
        args.get_akl_addon_id(),
        args.get_entity_id(),
        args.get_webserver_host(),
        args.get_webserver_port())
    
    if launcher.build():
        launcher.store_settings()
        return
    
    kodi.notify_warn('Cancelled creating launcher')


# ---------------------------------------------------------------------------------------------
# Scanner methods.
# ---------------------------------------------------------------------------------------------
# Arguments: --akl_addon_id --entity_id --entity_type --server_host --server_port
def scan_for_roms(args: addons.AklAddonArguments):
    logger.debug('Nvidia Gamestream scanner: Starting scan ...')
    progress_dialog = kodi.ProgressDialog()

    addon_dir = kodi.getAddonDir()
    report_path = addon_dir.pjoin('reports')
            
    scanner = NvidiaStreamScanner(
        report_path,
        args.get_entity_id(),
        args.get_webserver_host(),
        args.get_webserver_port(),
        progress_dialog)
        
    scanner.scan()
    progress_dialog.endProgress()
    
    logger.debug('Finished scanning')
    
    amount_dead = scanner.amount_of_dead_roms()
    if amount_dead > 0:
        logger.info(f'{amount_dead} roms marked as dead')
        scanner.remove_dead_roms()
        
    amount_scanned = scanner.amount_of_scanned_roms()
    if amount_scanned == 0:
        logger.info('No roms scanned')
    else:
        logger.info(f'{amount_scanned} roms scanned')
        scanner.store_scanned_roms()
        
    kodi.notify('ROMs scanning done')


# Arguments: --akl_addon_id (opt) --romcollection_id
def configure_scanner(args: addons.AklAddonArguments):
    logger.debug('Nvidia Gamestream scanner: Configuring ...')
    addon_dir = kodi.getAddonDir()
    report_path = addon_dir.pjoin('reports')
    
    scanner = NvidiaStreamScanner(
        report_path,
        args.get_entity_id(),
        args.get_webserver_host(),
        args.get_webserver_port(),
        kodi.ProgressDialog())
    
    if scanner.configure():
        scanner.store_settings()
        return
    
    kodi.notify_warn('Cancelled configuring scanner')


# ---------------------------------------------------------------------------------------------
# RUN
# ---------------------------------------------------------------------------------------------
try:
    run_plugin()
except Exception as ex:
    logger.fatal('Exception in plugin', exc_info=ex)
    kodi.notify_error("General failure")
