# -*- coding: utf-8 -*-
#
# Nvidia Gamestream plugin for AKL
#
# --- Python standard library ---
from __future__ import unicode_literals
from __future__ import division

import sys
import argparse
import logging
import json
    
# --- Kodi stuff ---
import xbmcaddon

# AKL main imports
from akl import constants, settings
from akl.utils import kodilogging, io, kodi
from akl.launchers import ExecutionSettings, get_executor_factory

# Local modules
from resources.lib.launcher import NvidiaGameStreamLauncher
from resources.lib.scanner import NvidiaStreamScanner

kodilogging.config() 
logger = logging.getLogger(__name__)

# --- Addon object (used to access settings) ---
addon           = xbmcaddon.Addon()
addon_id        = addon.getAddonInfo('id')
addon_version   = addon.getAddonInfo('version')

# ---------------------------------------------------------------------------------------------
# This is the plugin entry point.
# ---------------------------------------------------------------------------------------------
def run_plugin():
    # --- Some debug stuff for development ---
    logger.info('------------ Called Advanced Kodi Launcher Plugin: Nvidia Gamestream ------------')
    logger.info('addon.id         "{}"'.format(addon_id))
    logger.info('addon.version    "{}"'.format(addon_version))
    logger.info('sys.platform     "{}"'.format(sys.platform))
    if io.is_android(): logger.info('OS               "Android"')
    if io.is_windows(): logger.info('OS               "Windows"')
    if io.is_osx():     logger.info('OS               "OSX"')
    if io.is_linux():   logger.info('OS               "Linux"')
    for i in range(len(sys.argv)): logger.info('sys.argv[{}] "{}"'.format(i, sys.argv[i]))
    
    parser = argparse.ArgumentParser(prog='script.akl.nvgamestream')
    parser.add_argument('--cmd', help="Command to execute", choices=['launch', 'scan', 'scrape', 'configure'])
    parser.add_argument('--type',help="Plugin type", choices=['LAUNCHER', 'SCANNER', 'SCRAPER'], default=constants.AddonType.LAUNCHER.name)
    parser.add_argument('--server_host', type=str, help="Host")
    parser.add_argument('--server_port', type=int, help="Port")
    parser.add_argument('--rom_id', type=str, help="ROM ID")
    parser.add_argument('--romcollection_id', type=str, help="ROM Collection ID")
    parser.add_argument('--akl_addon_id', type=str, help="Addon configuration ID")
    parser.add_argument('--settings', type=json.loads, help="Specific run setting")
    
    try:
        args = parser.parse_args()
    except Exception as ex:
        logger.error('Exception in plugin', exc_info=ex)
        kodi.dialog_OK(text=parser.usage)
        return
    
    if   args.type == constants.AddonType.LAUNCHER.name and args.cmd == 'launch': launch_rom(args)
    elif args.type == constants.AddonType.LAUNCHER.name and args.cmd == 'configure': configure_launcher(args)
    elif args.type == constants.AddonType.SCANNER.name  and args.cmd == 'scan': scan_for_roms(args)
    elif args.type == constants.AddonType.SCANNER.name  and args.cmd == 'configure': configure_scanner(args)
    else:
        kodi.dialog_OK(text=parser.format_help())
    
    logger.debug('Advanced Kodi Launcher Plugin: Nvidia Gamestream -> exit')

# ---------------------------------------------------------------------------------------------
# Launcher methods.
# ---------------------------------------------------------------------------------------------
# Arguments: --akl_addon_id --rom_id
def launch_rom(args):
    logger.debug('Nvidia Gamestream Launcher: Starting ...')
    
    try:
        execution_settings = ExecutionSettings()
        execution_settings.delay_tempo              = settings.getSettingAsInt('delay_tempo')
        execution_settings.display_launcher_notify  = settings.getSettingAsBool('display_launcher_notify')
        execution_settings.is_non_blocking          = settings.getSettingAsBool('is_non_blocking')
        execution_settings.media_state_action       = settings.getSettingAsInt('media_state_action')
        execution_settings.suspend_audio_engine     = settings.getSettingAsBool('suspend_audio_engine')
        execution_settings.suspend_screensaver      = settings.getSettingAsBool('suspend_screensaver')
        execution_settings.suspend_joystick_engine  = settings.getSettingAsBool('suspend_joystick')
                
        addon_dir = kodi.getAddonDir()
        report_path = addon_dir.pjoin('reports')
        if not report_path.exists(): report_path.makedirs()    
        report_path = report_path.pjoin('{}-{}.txt'.format(args.akl_addon_id, args.rom_id))
        
        executor_factory = get_executor_factory(report_path)
        launcher = NvidiaGameStreamLauncher(
            args.akl_addon_id, 
            args.romcollection_id, 
            args.rom_id, 
            args.server_host, 
            args.server_port,
            executor_factory, 
            execution_settings)
        
        launcher.launch()
    except Exception as e:
        logger.error('Exception while executing ROM', exc_info=e)
        kodi.notify_error('Failed to execute ROM')    

# Arguments: --akl_addon_id --romcollection_id | --rom_id
def configure_launcher(args):
    logger.debug('Nvidia Gamestream Launcher: Configuring ...')
        
    launcher = NvidiaGameStreamLauncher(
            args.akl_addon_id, 
            args.romcollection_id, 
            args.rom_id, 
            args.server_host, 
            args.server_port)
    
    if launcher.build():
        launcher.store_settings()
        return
    
    kodi.notify_warn('Cancelled creating launcher')

# ---------------------------------------------------------------------------------------------
# Scanner methods.
# ---------------------------------------------------------------------------------------------
# Arguments: --akl_addon_id --romcollection_id --server_host --server_port
def scan_for_roms(args):
    logger.debug('Nvidia Gamestream scanner: Starting scan ...')
    progress_dialog = kodi.ProgressDialog()

    addon_dir = kodi.getAddonDir()
    report_path = addon_dir.pjoin('reports')
            
    scanner = NvidiaStreamScanner(
        report_path, 
        args.akl_addon_id,
        args.romcollection_id,
        args.server_host, 
        args.server_port, 
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
def configure_scanner(args):
    logger.debug('Nvidia Gamestream scanner: Configuring ...')    
    addon_dir = kodi.getAddonDir()
    report_path = addon_dir.pjoin('reports')
    
    scanner = NvidiaStreamScanner(
        report_path, 
        args.akl_addon_id,
        args.romcollection_id, 
        args.server_host, 
        args.server_port, 
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
    