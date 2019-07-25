'''
Created on Feb 21, 2017
@author: jchanda
'''
import time
import sys
import logging
import re
import inspect
import json
import os
import shutil

from collections import defaultdict
from common_utils import dump_error_in_lib, get_host_mgmt_ip
from linux_utils import LinuxUtils
import common_utils
from ecdsa.ecdsa import __main__


logger = logging.getLogger(__name__)

__author__ = 'Suren Kumar Moorthy <suremoor@cisco.com>'
__copyright__ = 'Copyright 2016, Cisco Systems'
__email__ = 'suremoor@cisco.com'
__date__ = 'Nov 7,2016'
__version__ = 1.0


class BiosUtils():

    def __init__(self, cimc_obj, config=None, common_config=None):
        self.handle = cimc_obj.handle
        self.cimc_obj = cimc_obj
        self.remote_ip = None
        self.cap_image_file_path = None
        self.config = config
        self.common_config = common_config

        self.tftp_ip = self.common_config.tftp_share.tftp_server_ip
        self.tftp_user = self.common_config.tftp_share.tftp_user
        self.tftp_password = self.common_config.tftp_share.tftp_password
        self.tftp_handle = LinuxUtils(self.tftp_ip, self.tftp_user, self.tftp_password)
        self.tftp_root_dir = self.common_config.tftp_share.tftp_root_path
        self.host_ip = get_host_mgmt_ip(config)

    def select_token_scope(self, token):
        ''' BIOS token Dictionary '''
        # M5 platform bios token Dictionary
        m5_token_dict = {
            'memory': ['MemoryMappedIOAbove4GB', 'NUMAOptimize', 'SelectMemoryRAS'],
            'processor': ['CoreMultiProcessing', 'EnhancedIntelSpeedStep', 'ExecuteDisable', 'IntelHyperThread', 'IntelTurboBoostTech',
                          'IntelVT', 'LocalX2Apic', 'ProcessorC1E', 'ProcessorC6Report'],
            'security': ['PowerOnPassword', 'TPMControl', 'TXTSupport'],
            'server-management': ['BORCoolDown', 'BORNumRetry', 'BaudRate', 'BootOptionRetry', 'ConsoleRedir', 'FRB-2', 'FlowCtrl',
                                  'OSBootWatchdogTimer', 'OSBootWatchdogTimerPolicy', 'OSBootWatchdogTimerTimeout', 'TerminalType',
                                  'cdnEnable'],
            'power-or-performance': ['AdjacentCacheLinePrefetch', 'CPUPerformance', 'DcuIpPrefetch', 'DcuStreamerPrefetch',
                                     'HardwarePrefetch'],
            'input-output': ['ATS', 'AllLomPortControl', 'AllPCIeSlotsOptionROM', 'CoherencySupport', 'IntelVTD', 'LomOpromControlPort0',
                             'LomOpromControlPort1', 'PcieSlot1LinkSpeed', 'PcieSlot1OptionROM', 'PcieSlot2LinkSpeed', 'PcieSlot2OptionROM',
                             'PcieSlotFrontNvme1LinkSpeed', 'PcieSlotFrontNvme2LinkSpeed', 'PcieSlotHBALinkSpeed', 'PcieSlotHBAOptionROM',
                             'PcieSlotMLOMLinkSpeed', 'PcieSlotMLOMOptionROM', 'PcieSlotN1OptionROM', 'PcieSlotN2OptionROM',
                             'SataModeSelect', 'UsbLegacySupport', 'VgaPriority', 'pSATA']
        }
        # M4 platform bios token Dictionary
        m4_token_dict = {
            'main': ['POPSupport', 'TPMAdminCtrl'],
            'server-management': ['FRB-2', 'OSBootWatchdogTimer', 'OSBootWatchdogTimerPolicy', 'OSBootWatchdogTimerTimeout'],
            'advanced': ['ASPMSupport', 'ATS', 'AdjacentCacheLinePrefetch', 'AllLomPortControl', 'AllUsbDevices', 'Altitude',
                         'AutonumousCstateEnable', 'BaudRate', 'BootPerformanceMode', 'CPUPowerManagement', 'ChannelInterLeave',
                         'CmciEnable', 'CoherencySupport', 'ConsoleRedir', 'CoreMultiProcessing', 'CpuEngPerfBias',
                         'CpuPerformanceProfile', 'DcuIpPrefetch', 'DcuStreamerPrefetch', 'DemandScrub', 'DirectCacheAccess',
                         'EnhancedIntelSpeedStep', 'ExecuteDisable', 'FlowCtrl', 'HWPMEnable', 'HardwarePrefetch', 'IntelHyperThread',
                         'IntelTurboBoostTech', 'IntelVT', 'IntelVTD', 'InterruptRemap', 'LegacyUSBSupport', 'LocalX2Apic',
                         'LomOpromControlPort0', 'LomOpromControlPort1', 'MemoryMappedIOAbove4GB', 'NUMAOptimize', 'PCIROMCLP',
                         'PCIeSSDHotPlugSupport', 'PackageCstateLimit', 'PassThroughDMA', 'PatrolScrub', 'PchUsb30Mode', 'PcieOptionROMs',
                         'PcieSlot1OptionROM', 'PcieSlot2OptionROM', 'PcieSlotFrontSlot5LinkSpeed', 'PcieSlotFrontSlot6LinkSpeed',
                         'PcieSlotHBALinkSpeed', 'PcieSlotHBAOptionROM', 'PcieSlotMLOMLinkSpeed', 'PcieSlotMLOMOptionROM',
                         'PcieSlotN1OptionROM', 'PcieSlotN2OptionROM', 'PcieSlotRiser1LinkSpeed', 'PcieSlotRiser2LinkSpeed',
                         'ProcessorC1E', 'ProcessorC3Report', 'ProcessorC6Report', 'PsdCoordType', 'PuttyFunctionKeyPad',
                         'PwrPerfTuning', 'QPILinkFrequency', 'QpiSnoopMode', 'RankInterLeave', 'RedirectionAfterPOST',
                         'SataModeSelect', 'SelectMemoryRAS', 'SrIov', 'TerminalType', 'UsbEmul6064', 'UsbPortFront',
                         'UsbPortInt', 'UsbPortKVM', 'UsbPortRear', 'UsbPortVMedia', 'UsbXhciSupport', 'VgaPriority', 'WorkLdConfig',
                         'cdnEnable', 'comSpcrEnable']
        }
        platform_type = self.config.mgmtdetail.platform_series
        logger.info('Platform Series Type is: ' + platform_type)
        if platform_type == 'M4':
            token_dict = m4_token_dict
        elif platform_type == 'M5':
            token_dict = m5_token_dict
        else:
            logger.error('Unable to detect platform series type. Please check whether defined in config file or not.\
                        if not please update config file with server series type.')
            return False
        for key in token_dict:
            if token in token_dict[key]:
                logger.info('"%s" token is associated with "%s" scope' % (token, key))
                return key
        logger.error('Failed to locate "%s" token with its corresponding scope' % (token))
        return False

    def token_map(self):
        platform_type = self.config.mgmtdetail.platform_series
        if platform_type == 'M4':
            token_supp_val = 'COM_0'
        elif platform_type == 'M5':
            token_supp_val = 'COM_0'
        else:
            logger.error('Unable to detect platform series type:' + platform_type)
            return False
        return token_supp_val

    def enable_disable_sol(self, value='no'):
        ''' Procedure to enable or disable SOL'''
        self.handle.execute_cmd_list('top', 'scope sol', 'set enabled ' + value)
        commit_out = self.handle.execute_cmd('commit', wait_time=8)
        if re.search('ERROR', commit_out, re.IGNORECASE):
            logger.info('Unable commit SOL parameters' + str(commit_out))
            self.handle.execute_cmd('discard')
            return False
        return True

    def get_bios_token_value(self, token):
        '''
        Procedure to get bios values by passing its token name
        Parameter:
        param: Default - None
                  or
               Pass the appropriate name of the token to get the value
               (Pass sub scope name to get token values inside sub scopes
                like advance,server-management,main,bios-profile,boot-device)

        Return:
            Token value: Success
            False : Failure

        Author: Suren kumar Moorthy
       '''
        logger.info('Getting bios token value')
        sub_scope = self.select_token_scope(token)
        if sub_scope is False:
            logger.error('Failed to get "%s" token associated scope mapping' % (token))
            return False
        try:
            if sub_scope is None:
                out = self.handle.execute_cmd_list('top', 'scope bios', 'show detail', wait_time=8)
            else:
                out = self.handle.execute_cmd_list('top', 'scope bios', 'scope ' +
                                                   sub_scope, 'show detail', wait_time=8)
            logger.info(out)
            regex = token + r'\s*\:\s+([^\r\n]+)'
            return re.search(regex, out).group(1)
        except:
            dump_error_in_lib()
            return False

    def set_bios_token_value(self, token, new_value, reboot='yes', commit_wait=150):
        '''
        Procedure to get bios values by passing its token name

        Parameter:
        param: Default - None
                  or
               Pass the appropriate name of the token to get the value
               (Pass sub scope name to get token values inside sub scopes
                like advance,server-management,main,bios-profile,boot-device)

        Return:
            Token value: Success
            False : Failure

        Author: Suren kumar Moorthy
        '''
        logger.info('Getting bios token value')
        sub_scope = self.select_token_scope(token)
        if sub_scope is False:
            logger.error('Failed to get "%s" token associated scope mapping')
            return False
        try:
            if sub_scope is None:
                self.handle.execute_cmd_list('top', 'scope bios')
            else:
                self.handle.execute_cmd_list('top', 'scope bios', 'scope ' + sub_scope)
            time.sleep(3)
            out = self.handle.execute_cmd('set ' + token + ' ' + new_value, wait_time=8)
            match = re.search('invalid|exceeding|incomplete|Valid value\
                                |cannot be used', out, re.I)
            time.sleep(2)
            if match is not None:
                logger.error('Failed to execute command; got error as: ' + str(match))
                return False
            commit_out = self.handle.execute_cmd('commit', wait_time=commit_wait)
            logger.info('commit out is ' + token + ' to ' + new_value + ' : ' + str(commit_out))
            if re.search('ERROR', commit_out, re.IGNORECASE):
                logger.info('Unable to set parameter ' + token +
                            ' to ' + new_value + ' : ' + str(commit_out))
                self.handle.execute_cmd('discard')
                return False
            if 'Do you want to reboot the system' in commit_out or 'Your changes will be reflected' in commit_out:
                logger.info('inside Do u want to reboot check')
                if reboot is 'yes':
                    reboot_out = self.handle.execute_cmd('y', wait_time=150)
                    if 'A system reboot has been initiated' in reboot_out:
                        logger.info('Successfully set the token ' +
                                    token + ' and host reboot initiated.')
                        time.sleep(180)
                    else:
                        logger.error('Failed to initiate host reboot after setting bios token')
                        return False

                else:
                    reboot_out = self.handle.execute_cmd('N', wait_time=6)
                    if 'Changes will be applied on next reboot' in reboot_out:
                        logger.info('Successfully set the token, \
                                    changes will reflect in next host reboot')
                    else:
                        logger.error('Failed to set' + token + ' to new value ' + new_value)
                        return False
            else:
                logger.warn('Unexpected output')
                return False
            return True
        except:
            curframe = inspect.currentframe()
            calframe = inspect.getouterframes(curframe, 2)
            logger.error("Error occured at the library function call name :" + str(calframe[1][3]))
            logger.error("Error occured is " + sys.exc_info().__str__())
            return False
        return True

    def load_bios_defaults(self, clear_cmos=None, restore='Yes'):
        '''
        Procedure to set bios tokens to default values
        Parameter:
            None
        Return:
            True  : Success
            False : Failure
        Author: jchanda
        '''
        try:
            if clear_cmos is None:
                out = self.handle.execute_cmd_list('top', 'scope bios',
                                                   'bios-setup-default', wait_time=6)
            else:
                out = self.handle.execute_cmd_list('top', 'scope bios', 'clear-cmos', wait_time=6)
            if 'Continue' in out:
                out = self.handle.execute_cmd('y')
                if re.search('Error', out):
                    logger.error('Failed to perform operation. Got Error Msg: ' + out)
                    return False
                time.sleep(180)
                logger.info("Waiting for host to come up")
                if restore == 'Yes':
                    if self.set_bios_token_value("ConsoleRedir", self.token_map(),
                                                 commit_wait=150) is False:
                        logger.error("Failed to set consoleRedir")
                        return False
        except:
            dump_error_in_lib()
            return False
        return True

    def restore_tokens_to_defaults(self, restore_type):
        '''
        Procedure to set bios tokens to default values
        Parameter:
            None
        Return:
            True  : Success
            False : Failure
        Author: jchanda
        '''
        try:
            logger.info('Performing bios restore operation: %s' % (restore_type))
            self.handle.execute_cmd_list('top', 'scope bios')

            if restore_type == 'bios-setup-default':
                out = self.handle.execute_cmd('bios-setup-default')
            elif restore_type == 'clear-cmos':
                # Power off the system to run clear-cmos command
                self.cimc_obj.set_host_power('off')
                out = self.handle.execute_cmd_list('top', 'scope bios', 'clear-cmos')
            elif restore_type == 'restore-mfg-defaults':
                # Power off the system to run restore-mfg-defaults command
                self.cimc_obj.set_host_power('off')
                out = self.handle.execute_cmd_list('top', 'scope bios', 'restore-mfg-defaults')
            else:
                logger.warning('Invalid bios token restore option: %s' % (restore_type))
                return False

            if 'Continue' in out:
                out = self.handle.execute_cmd('y')
                if re.search('Error', out):
                    logger.error('Failed to perform %s operation. Got Error Msg: %s ' % (restore_type, out))
                    return False
                logger.info("Waiting for host to come up")
                res = self.cimc_obj.verify_host_up(hostname=self.host_ip, wait_for_ping_fail=False)
                if res is False:
                    logger.warning('Failed to ping the host')
        except:
            dump_error_in_lib()
            return False
        logger.info('Successfully performed operation %s' % (restore_type))
        return True

    def restore_mfg_defaults(self):
        '''
        Procedure to Reset BIOS setup parameters to manufacturing defaults
        '''
        # Power off the system to run restore-mfg-defaults command
        if self.cimc_obj.set_host_power('off') is False:
            logger.error('Failed to power of host')
            return False

        out = self.handle.execute_cmd_list('top', 'scope bios', 'restore-mfg-defaults')
        if 'Continue' in out:
            self.handle.execute_cmd('y')
        else:
            logger.error('Failed: restore-mfg-defaults operation failed')
            return False

        logger.info('Host will be powered on. Will wait for host to ping')
        res = self.cimc_obj.verify_host_up(hostname=self.host_ip, wait_for_ping_fail=False)
        if res is False:
            logger.warning('Failed to ping the host')

        logger.info('Passed: restore-mfg-defaults operation succeeds')
        return True

    def get_bios_token_value_list(self, token=[]):
        '''
        Procedure to get bios values by passing its token name
        Parameter:
        param: Default - None
                  or
               Pass the appropriate name of the token list to get the value
               (Pass sub scope name to get token values inside sub scopes
                like advance,server-management,main,bios-profile,boot-device)

        Return:
            Token value in dictionary format: Success
            False : Failure

        Author: Suren kumar Moorthy
       '''
        logger.info('Getting bios token value')
        try:
            token_dict = defaultdict(dict)
            for tok in token:
                sub_scope = self.select_token_scope(tok)
                if sub_scope is False:
                    logger.error('Failed to get "%s" token associated scope mapping' % (tok))
                    return False
                out = self.handle.execute_cmd_list('top', 'scope bios',
                                                   'scope ' + sub_scope, 'show detail')
                logger.info(out)
                regex = tok + r'\s*\:\s+([^\r\n]+)'
                token_dict[tok] = re.search(regex, out).group(1)
            return token_dict
        except:
            dump_error_in_lib()
            return False

    def set_bios_token_value_list(self, token_dict, reboot='yes', commit_wait=150):
        '''
        Procedure to get bios values by passing its token name

        Parameter:
        param: Default - None
                  or
               Pass the appropriate name of the token to get the value
               (Pass sub scope name to get token values inside sub scopes
                like advance,server-management,main,bios-profile,boot-device)

        Return:
            Token value: Success
            False : Failure

        Author: Suren kumar Moorthy
        '''
        logger.info('Getting bios token value')
        try:

            for token, new_value in token_dict.items():
                sub_scope = self.select_token_scope(token)
                if sub_scope is False:
                    logger.error('Failed to get "%s" token associated scope mapping')
                    return False
                self.handle.execute_cmd_list('top', 'scope bios', 'scope ' + sub_scope)
                out = self.handle.execute_cmd('set ' + token + ' ' + str(new_value))
                match = re.search('invalid|exceeding|incomplete|Valid value| \
                                    Maximum|cannot be used', out, re.I)
                if match is not None:
                    logger.error('Failed to execute command; got error as: ' + str(match))
                    return False
            commit_out = self.handle.execute_cmd('commit', wait_time=commit_wait)
            logger.info("commit output :" + commit_out)
            if re.search('ERROR', commit_out, re.IGNORECASE):
                logger.info('Unable to set parameter ' + str(commit_out))
                self.handle.execute_cmd('discard')
                return False
            elif re.search('Do you want to reboot the system', commit_out) and reboot is 'yes':
                reboot_out = self.handle.execute_cmd('y', wait_time=60)
                if 'A system reboot has been initiated' in reboot_out:
                    logger.info('Successfully set the token and host reboot initiated.')
                    time.sleep(180)
                else:
                    logger.error('Failed to initiate host reboot after setting bios token')
                    return False
            elif reboot is not 'yes':
                reboot_out = self.handle.execute_cmd('N')
                if 'Changes will be applied on next reboot' in reboot_out:
                    logger.info('Successfully set the token, \
                                 changes will reflect in next host reboot')
                else:
                    logger.error('Failed to set to new value ')
                    return False
            else:
                return False
            return True
        except:
            dump_error_in_lib()
            return False
        return True

    def console_redirect_defaults(self):
        '''
            Procedure to set defaults of console redirect
            ConsoleRedir COM_0
            TerminalType VT100+
            BaudRate 115200
            FlowCtrl None
            PuttyFunctionKeyPad ESCN
            RedirectionAfterPOST Always_Enable

            This procedure checks all console redirection tokens have
            default value and if not make it default

            Return:
            True: Success
            False : Failure

            Author: Suren kumar Moorthy
        '''
        try:
            logger.info("Verify console redirection paramters are in defaults")
            platform_type = self.config.mgmtdetail.platform_series
            logger.info('Platform Series Type is: ' + platform_type)
            if platform_type == 'M4':
                token_dict = {"ConsoleRedir": self.token_map(), "TerminalType": "VT100+",
                              "BaudRate": "115200", "FlowCtrl": "None",
                              "PuttyFunctionKeyPad": "ESCN", "RedirectionAfterPOST": "Always_Enable"}
                out_dict = self.get_bios_token_value_list(['ConsoleRedir', 'TerminalType', 'BaudRate',
                                                           'FlowCtrl', 'PuttyFunctionKeyPad',
                                                           'RedirectionAfterPOST'])
            else:
                token_dict = {"ConsoleRedir": self.token_map(), "TerminalType": "VT100-PLUS",
                              "BaudRate": "115.2k", "FlowCtrl": "None"}
                out_dict = self.get_bios_token_value_list(['ConsoleRedir', 'TerminalType', 'BaudRate',
                                                           'FlowCtrl'])
            set_toke_dict = defaultdict(dict)
            change_flag = 0
            for token, value in out_dict.items():
                if token_dict[token] != out_dict[token]:
                    set_toke_dict[token] = token_dict[token]
                    change_flag = 1
            if change_flag == 1:
                if self.set_bios_token_value_list(set_toke_dict) is True:
                    logger.info("Setting default console redirect successful")
                    return True
                else:
                    logger.error("Failed to set default values in console redirection")
                    return False
            else:
                logger.info("Console redirect has default values.")
                return True
        except:
            dump_error_in_lib()
            return False

    def set_common_token_value(self, token, new_value, scope, sub_scope=None, reboot='yes', commit_wait=120):
        '''
        Procedure to get bios values by passing its token name

        Parameter:
        param: Default - None
                  or
               Pass the appropriate name of the token to get the value
               (Pass sub scope name to get token values inside sub scopes
                like advance,server-management,main,bios-profile,boot-device)

        Return:
            Token value: Success
            False : Failure

        Author: Suren kumar Moorthy
        '''
        logger.info('Getting bios token value')
        try:
            if sub_scope is None:
                self.handle.execute_cmd_list('top', 'scope ' + scope)
            else:
                self.handle.execute_cmd_list('top', 'scope ' + scope, 'scope ' + sub_scope)
            time.sleep(3)
            out = self.handle.execute_cmd('set ' + token + ' ' + new_value, wait_time=8)
            match = re.search('invalid|exceeding|incomplete|Valid value\
                                |Maximum|cannot be used', out, re.I)
            time.sleep(2)
            if match is not None:
                logger.error('Failed to execute command; got error as: ' + str(match))
                return False
            commit_out = self.handle.execute_cmd('commit', wait_time=commit_wait)
            logger.info('commit out is ' + token + ' to ' + new_value + ' : ' + str(commit_out))
            if re.search('ERROR', commit_out, re.IGNORECASE):
                logger.info('Unable to set parameter ' + token +
                            ' to ' + new_value + ' : ' + str(commit_out))
                self.handle.execute_cmd('discard')
                return False
            if 'Do you want to reboot the system' in commit_out:
                logger.info('inside Do u want to reboot check')
                if reboot is 'yes':
                    reboot_out = self.handle.execute_cmd('y', wait_time=120)
                    if 'A system reboot has been initiated' in reboot_out:
                        logger.info('Successfully set the token ' +
                                    token + ' and host reboot initiated.')
                        time.sleep(180)
                    else:
                        logger.error('Failed to initiate host reboot after setting bios token')
                        return False

                else:
                    reboot_out = self.handle.execute_cmd('N', wait_time=6)
                    if 'Changes will be applied on next reboot' in reboot_out:
                        logger.info('Successfully set the token, \
                                    changes will reflect in next host reboot')
                    else:
                        logger.error('Failed to set' + token + ' to new value ' + new_value)
                        return False
            elif self.get_common_token_value(token, scope, sub_scope) == new_value:
                return True
            else:
                logger.warn('Unexpected output')
                return False
            return True
        except:
            curframe = inspect.currentframe()
            calframe = inspect.getouterframes(curframe, 2)
            logger.error("Error occured at the library function call name :" + str(calframe[1][3]))
            logger.error("Error occured is " + sys.exc_info().__str__())
            return False
        return True

    def get_common_token_value(self, token, scope, sub_scope=None):
        '''
        Procedure to get bios values by passing its token name
        Parameter:
        param: Default - None
                  or
               Pass the appropriate name of the token to get the value
               (Pass sub scope name to get token values inside sub scopes
                like advance,server-management,main,bios-profile,boot-device)

        Return:
            Token value: Success
            False : Failure

        Author: Suren kumar Moorthy
       '''
        logger.info('Getting bios token value')
        try:
            if sub_scope is None:
                out = self.handle.execute_cmd_list('top', 'scope ' + scope, 'show detail', wait_time=8)
            else:
                out = self.handle.execute_cmd_list('top', 'scope ' + scope, 'scope ' +
                                                   sub_scope, 'show detail', wait_time=8)
            logger.info(out)
            regex = token + r'\s*\:\s+([^\r\n]+)'
            return re.search(regex, out).group(1)
        except:
            dump_error_in_lib()
            return False

    global default_token_dict
    default_token_dict = {
        'input_output': {'ATS': 'Enabled',
                         'AllLomPortControl': 'Enabled',
                         'CoherencySupport': 'Disabled',
                         'IPV6PXE': 'Disabled',
                         'IntelVTD': 'Enabled',
                         'LomOpromControlPort0': 'Enabled',
                         'LomOpromControlPort1': 'Enabled',
                         'PcieSlot1LinkSpeed': 'Auto',
                         'PcieSlot1OptionROM': 'Enabled',
                         'PcieSlot2LinkSpeed': 'Auto',
                         'PcieSlot2OptionROM': 'Enabled',
                         'PcieSlot3LinkSpeed': 'Auto',
                         'PcieSlot3OptionROM': 'Enabled',
                         'PcieSlot4LinkSpeed': 'Auto',
                         'PcieSlot4OptionROM': 'Enabled',
                         'PcieSlot5LinkSpeed': 'Auto',
                         'PcieSlot5OptionROM': 'Enabled',
                         'PcieSlot6LinkSpeed': 'Auto',
                         'PcieSlot6OptionROM': 'Enabled',
                         'PcieSlotFrontNvme1LinkSpeed': 'Auto',
                         'PcieSlotFrontNvme2LinkSpeed': 'Auto',
                         'PcieSlotMLOMLinkSpeed': 'Auto',
                         'PcieSlotMLOMOptionROM': 'Enabled',
                         'PcieSlotMRAIDLinkSpeed': 'Auto',
                         'PcieSlotMRAIDOptionROM': 'Enabled',
                         'PcieSlotN1OptionROM': 'Enabled',
                         'PcieSlotN2OptionROM': 'Enabled',
                         'PcieSlotRearNvme1LinkSpeed': 'Auto',
                         'PcieSlotRearNvme1OptionRom': 'Enabled',
                         'PcieSlotRearNvme2LinkSpeed': 'Auto',
                         'PcieSlotRearNvme2OptionRom': 'Enabled',
                         'SataModeSelect': 'AHCI',
                         'UsbLegacySupport': 'Enabled',
                         'UsbPortFront': 'Enabled',
                         'UsbPortInt': 'Enabled',
                         'UsbPortKVM': 'Enabled',
                         'UsbPortRear': 'Enabled',
                         'UsbPortSdCard': 'Enabled',
                         'VgaPriority': 'Onboard',
                         'pSATA': 'LSI_SW_RAID'
                         },
        'server_management': {'BaudRate': '115.2k',
                              'ConsoleRedir': 'Disabled',
                              'FRB-2': 'Enabled',
                              'FlowCtrl': 'None',
                              'OSBootWatchdogTimer': 'Disabled',
                              'OSBootWatchdogTimerPolicy': 'Power_Off',
                              'OSBootWatchdogTimerTimeout': '10_minutes',
                              'TerminalType': 'VT100',
                              'cdnEnable': 'Enabled'
                              },
        'memory': {'MemoryMappedIOAbove4GB': 'Enabled',
                   'NUMAOptimize': 'Enabled',
                   'SelectMemoryRAS': 'Maximum_Performance'
                   },
        'power_or_performance': {'AdjacentCacheLinePrefetch': 'Enabled',
                                 #'CPUPerformance' : 'Custom',
                                 'DcuIpPrefetch': 'Enabled',
                                 'DcuStreamerPrefetch': 'Enabled',
                                 'HardwarePrefetch': 'Enabled'
                                 },
        'processor': {'BootPerformanceMode': 'Max_Performance',
                      'CoreMultiProcessing': 'All',
                      'CpuEngPerfBias': 'Balanced_Performance',
                      'CpuHWPM': 'HWPM_Native_Mode',
                      'EnhancedIntelSpeedStep': 'Enabled',
                      'ExecuteDisable': 'Enabled',
                      'IMCInterleave': 'Auto',
                      'IntelHyperThread': 'Enabled',
                      'IntelTurboBoostTech': 'Enabled',
                      'IntelVT': 'Enabled',
                      'KTIPrefetch': 'Enabled',
                      'LLCPrefetch': 'Disabled',
                      'LocalX2Apic': 'Disabled',
                      'PackageCstateLimit': 'C0_C1_State',
                      'ProcessorC1E': 'Disabled',
                      'ProcessorC6Report': 'Disabled',
                      'ProcessorCMCI': 'Enabled',
                      'PsdCoordType': 'HW_ALL',
                      'PwrPerfTuning': 'OS',
                      'SNC': 'Disabled',
                      'WorkLdConfig': 'IO_Sensitive',
                      'XPTPrefetch': 'Disabled',
                      'AutoCCState': 'Disabled',
                      'EnergyEfficientTurbo': 'Disabled',
                      'PatrolScrub': 'Enabled',
                      'EPPProfile': 'Balanced_Performance'    
                      },
        'security': {'PowerOnPassword': 'Disabled',
                     'TPMControl': 'Enabled',
                     'TXTSupport': 'Disabled'
                     }
    }

    def validate_default_tokens(self, bios_scope_dict, bios_scope):
        '''
        Procedure to validate default bios tokens after the CMOS clear operation
        Procedure to validate default bios tokens after the BIOS load default operation
        '''
        logger.info('Validating BIOS tokens for scope: {}'.format(bios_scope))
        logger.info('Current default values obtained from the testbed are:' + str(bios_scope_dict))
        logger.info('Actual expected default tokens for the testbed are: {}'.format(default_token_dict[bios_scope]))

        if common_utils.compare_dictionaries(default_token_dict[bios_scope], bios_scope_dict) is True:
            return True
        else:
            return False

    def validate_mfg_custom_default_tokens(self, bios_scope_dict, user_token_dict, bios_scope):
        '''
        Procedure to validate mfg default bios tokens after the restore-mfg-defaults

        Below are the some of the sample mfg tokens considred for the test:

        CPUPerformance : HPC
        OSBootWatchdogTimerPolicy : Reset
        FRB-2 : Disabled
        CoherencySupport : Enabled
        TPMControl : Disabled
        ATS : Disabled
        AdjacentCacheLinePrefetch : Disabled
        '''
        # CoherencySupport, default value:Disabled, User default value:Enabled
        # ATS, default value: Enabled, User default value:Disabled
        # FRB-2 default value:Enabled, User default value: Disabled
        # AdjacentCacheLinePrefetch: default value:Enabled, User default value: 'Disabled'
        # AdjacentCacheLinePrefetch: default value:Enabled, User default value: 'Disabled'
        # IntelVT: default value:Enabled, User default value: Disabled
        # PwrPerfTuning: default value:OS, User default value: BIOS
        # TPMControl default value:Enabled; User default value:Disabled

        for token, token_val in default_token_dict[bios_scope].items():
            logger.info('Default token value %s %s' % (token, token_val))
            print(token, token_val)
            if token in user_token_dict.keys():
                val = user_token_dict[token]
                default_token_dict[bios_scope][token] = '_'.join(val.split(' '))
                logger.info('Changed token values as per user mfg default token as %s %s' % (token, val))

        logger.info('After updating token dict as per user mfg default dict:')
        logger.info(default_token_dict[bios_scope])

        logger.info('Validating BIOS tokens for scope: {}'.format(bios_scope))
        logger.info('Current default values obtained from the testbed are:' + str(bios_scope_dict))
        logger.info('Actual expected default tokens for the testbed are: {}'.format(default_token_dict[bios_scope]))

        if common_utils.compare_dictionaries(default_token_dict[bios_scope], bios_scope_dict) is True:
            return True
        else:
            return False

    def create_bios_profile_and_copy2tftpshare(self, user_token_dict=None):
        '''
        Procedure to create BIOS token JSON format profile to install this profile on cimc
            to update the set of tokens
        Parameter:
            user_token_dict: bios token dictionary; if not passed will take default created one 
        Return:
            True  : Success
            False : Failure
        Author: jchanda
        '''
        # Some sample Bios token values other than default values for testing
        # clear-cmos and bios-setup-default operation
        token_dict_value = {'IntelHyperThread': 'Disabled',
                            'HardwarePrefetch': 'Disabled',
                            'AdjacentCacheLinePrefetch': 'Disabled',
                            'DcuStreamerPrefetch': 'Disabled',
                            'DcuIpPrefetch': 'Disabled',
                            'LLCPrefetch': 'Enabled',
                            'IntelTurboBoostTech': 'Disabled',
                            'CpuHWPM': 'Disabled',
                            'PackageCstateLimit': 'Auto',
                            'PwrPerfTuning': 'BIOS',
                            'NUMAOptimize': 'Disabled',
                            'IMCInterleave': '1-way Interleave',
                            'XPTPrefetch': 'Enabled',
                            'KTIPrefetch': 'Disabled',
                            'SNC': 'Auto'
                            }
        # create default dictionary
        token_dict = defaultdict(dict)
        token_dict['name'] = 'bios_profile'
        token_dict['description'] = 'bios token settings test'
        if user_token_dict is not None:
            token_dict['tokens'] = user_token_dict
        else:
            token_dict['tokens'] = token_dict_value

        # dump into json object
        bios_token_json_profile = json.dumps(token_dict)
        logger.info('Created the bios token json format: ' + bios_token_json_profile)

        # copy dump json string data into a file
        with open('bios_profile.json', 'w') as fh:
            fh.write(bios_token_json_profile)

        # copy json file to remote tftp share server
        logger.info('Copying json file to remote tftp share server')
        self.tftp_handle.connect()
        logger.info('Successfully connected to remote tftp server: ' + self.tftp_ip)

        logger.info('Creating bios_profile dir in remote server')
        remote_path = self.tftp_root_dir + '/' + 'bios_profile_dir'
        self.tftp_handle.execute_cmd('mkdir -p ' + remote_path)
        self.profile_name = 'bios_profile'
        self.json_relative_path = 'bios_profile_dir' + '/' + 'bios_profile.json'

        logger.info('Copying the bios token json format file to remote tftp share server')
        res = self.tftp_handle.copy_local_to_remote('bios_profile.json', remote_path + '/' + 'bios_profile.json')
        if res is not True:
            logger.error('Failed to copy bios json format file')
            return False
        else:
            logger.info('Successfully copied file bios json format fiel')
            return True

    def delete_bios_profile(self, profile_name=None):
        '''
        Procedure to delete the profile by passing the name of the profile
        Parameter:
            profile_name: to be deleted 
        Return:
            True  : Success
            False : Failure
        Author: jchanda
        '''
        self.handle.execute_cmd_list('top', 'scope bios', 'scope bios-profile')
        profile_name = self.profile_name
        out = self.handle.execute_cmd('delete ' + profile_name)
        if 'Error' in out:
            logger.warning('BIOS profile: %s does not exists. command output: %s' % (profile_name, out))
            return False
        elif 'Do you want to delete the active profile' in out:
            self.handle.execute_cmd('y')
            logger.info('Successfully deleted the bios profile')
            return True

    def install_and_activate_bios_profile(self, protocol=None, reboot=None):
        '''
        Procedure to install and activate the BIOS profile on CIMC
        Parameter:
            protocol: by default tftp will be taken
            reboot: yes; to reboot host
        Return:
            True  : Success
            False : Failure
        Author: jchanda
        '''

        self.handle.execute_cmd_list('top', 'scope bios', 'scope bios-profile')

        # delete if any existing bios profile is already installed on CIMC
        self.delete_bios_profile()

        # install the bios profile on CIMC
        if protocol is None:
            cmd = 'install ' + 'tftp' + ' ' + self.tftp_ip + ' ' + self.json_relative_path
        self.handle.execute_cmd(cmd)
        out = self.handle.execute_cmd('show detail')
        if 'validation success' not in out:
            logger.error('Failed to install the bios profile on cimc')
            return False

        # activate the bios profile
        profile_name = self.profile_name
        cmd = 'activate ' + profile_name
        out = self.handle.execute_cmd(cmd)
        if 'Do you want to continue with BIOS Profile activation' in out:
            out2 = self.handle.execute_cmd('y')
            if 'Do you want to take a backup of BIOS tokens' in out2:
                out3 = self.handle.execute_cmd('y')
                if 'Do you want to reboot the system' in out3:
                    if reboot is not None:
                        out4 = self.handle.execute_cmd('y')
                        if 'A system reboot has been initiated' in out4:
                            logger.info('Successfully activated bios profile %s' % (profile_name))
                            return True
                        else:
                            logger.error('Failed to activate the bios profile')
                            return False
                    else:
                        out4 = self.handle.execute_cmd('N')
                        if 'Changes will be applied on next reboot' in out4:
                            logger.info('Successfully activated bios profile %s' % (profile_name))
                            return True
                        else:
                            logger.error('Failed to activate the bios profile')
                            return False

    def load_bios_mfg_custom_tokens(self, user_defined_tokens_dic):
        '''
        Procedure will create token.txt file and edit file with custom mfg-def tokens,
            and load the file by executing SetMfgDefaults -f command.
        Parameter:
            user_defined_tokens_dic: User defined token dictionary to be applied on system
        Return:
            True  : Success
            False : Failure
        Author: jchanda
        '''
        logger.info('User defined tokens opted for mfg are: ' + str(user_defined_tokens_dic))
        cimc_debug_handle = self.cimc_obj.telnet_handle
        cimc_debug_handle.connect_to_mgmnt()

        # change the prompt to Linux shell
        prompt = 'linuxMode'
        cimc_debug_handle.set_bmc_serial_mode(prompt)

        # delete if any existing token file present; and create new one
        cimc_debug_handle.execute_cmd_serial('rm /tmp/token.txt &2>/dev/null')
        for keys, val in user_defined_tokens_dic.items():
            cmd = 'echo ' + keys + ' ' + ':' + ' ' + val + '>> /tmp/token.txt'
            cimc_debug_handle.execute_cmd_serial(cmd)

        # Load bios mfg tokens from debug shell
        cmd = 'SetMfgDefaults -f /tmp/token.txt'
        out = cimc_debug_handle.execute_cmd_serial(cmd)
        if 'Error' in out:
            logger.error('Failed: to load mfg bios token')
            return False
        elif 'Please restart host' in out:
            logger.info('Passed: successfully issued the command')

        # Power cycle the host
        logger.info('Need to restart host for manufacturing settings to take effect')
        if self.cimc_obj.power_cycle_host() is False:
            logger.error('Failed to power cycle the host')
            return False

        # Wait for host to come up
        res = self.cimc_obj.verify_host_up(hostname=self.host_ip, wait_for_ping_fail=False)
        if res is False:
            logger.warning('Failed to ping the host')

        logger.info('Passed: successfully loaded mfg bios tokens on CIMC')
        return True
