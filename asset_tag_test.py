'''
__author__ = 'Jagadish Chanda <jchanda@cisco.com>'
__copyright__ = 'Copyright 2017, Cisco Systems'
__email__ = 'jchanda@cisco.com'
__date__ = 'Sept 28,2017'
__ve
'''

import logging
import re
from ats import aetest

from common_utils import get_host_mgmt_ip
from linux_utils import LinuxUtils
from boot_order import BootOrder
from common_test import Setup, Cleanup
from host_utils import HostUtils

################################################################################
# Global class variable to maintain objects by creating one time and
# use all over the script
################################################################################
classparam = {}

# Get your logger for your script
log = logging.getLogger(__name__)

################# Common setup Starts ############################################


def asset_tag_puppet_desc_cli(self, cimc_util_obj):
    '''
        procedure to fetch assettag and puppet description from cli
    '''
    log.info("Fetching the asset tag info from chassis using CLI")
    out = cimc_util_obj.handle.execute_cmd_list('top', 'scope chassis', 'show detail')
    res = re.search(r'asset-tag:\s+([^\r\n]+)', out)
    res2 = re.search(r'description:\s+([^\r\n]+)', out)
    if res is not None and res2 is not None:
        self.asset_tag_cli = res.group(1).strip()
        self.puppet_desc_cli = res2.group(1).strip()
        log.info('CLI: AssetTag info: ' + self.asset_tag_cli)
        log.info('CLI: Description info: ' + self.puppet_desc_cli)
    else:
        log.error('Failed to get asset tag/puppet description')
        return False
    return True


def asset_tag_puppet_desc_host(self, config):
    '''
    Procedure to fetch assettag and puppet descriptin from host OS
    '''
    log.info('Fetch the Asset tag/Puppet description from host OS')
    host_detail_config = config.host_info[0].nw_intf_list[0]
    host_info_config = config.host_info[0].host_detail
    log.info("############# Host Info ##########")
    log.info("IP : " + host_detail_config.ip_address + "\n user : " +
             host_info_config.os_login + "\n pass : " + host_info_config.os_password)
    log.info("##################################")
    host_handle = LinuxUtils(host_detail_config.ip_address,
                             host_info_config.os_login, host_info_config.os_password)
    if host_handle.connect() is False:
        log.error("Unable to connect to host")
        return False
    else:
        # Fetch asset tag
        out = host_handle.execute_cmd('dmidecode -t 2')
        res = re.search(r'Asset Tag:\s+([^\r\n]+)', out)
        if res is not None:
            self.asset_tag_host = res.group(1).strip()
            log.info('Host: AssetTag info: ' + self.asset_tag_host)
        else:
            log.error('Failed to get asset tag info')
            return False
        # Fetch Puppet description
        out2 = host_handle.execute_cmd('dmidecode -t 11')
        res2 = re.search(r'String 2:\s+([^\r\n]+)', out2)
        if res2 is not None:
            self.puppet_desc_host = res2.group(1).strip()
            log.info('Host: Puppet Description info: ' + self.puppet_desc_host)
        else:
            log.error('Failed to get puppet description')
            return False
    return True


def asset_tag_puppet_desc_efi(self, cimc_util_obj, boot_order_obj):
    '''
    Procedure to fetch assettag and puppet description from efi
    '''
    log.info("Fetching the asset tag/puppet description from chassis using EFI Shell")
    host_serial_handle = cimc_util_obj.telnet_handle
    efi_connect_status = boot_order_obj.boot_to_efi_shell(post_flag=True)

    if efi_connect_status is not False:
        log.info("Successfully Booted to EFI shell")
        cmd1 = 'smbiosview -t 2'
        cmd2 = 'smbiosview -t 11'

        # Fetch AssetTag info
        efi_out1 = host_serial_handle.execute_cmd_serial_host(cmd1)
        # host_serial_handle.disconnect()
        log.info('EFI shell out .......' + efi_out1)
        res = re.search(r'AssetTag:\s+([^\r\n]+)', efi_out1)
        if res is not None:
            self.asset_tag_efi = res.group(1).strip()
            log.info('EFI Shell: AssetTag info: ' + self.asset_tag_efi)
        else:
            log.error('Failed to get asset tag info from EFI Shell')
            return False

        # Fetch Puppet description info
        efi_out2 = host_serial_handle.execute_cmd_serial_host(cmd2)
        log.info('EFI shell out .......' + efi_out2)
        lines = efi_out2.split('\n')
        if len(lines) == 0:
            log.error('Failed to get Puppet description from efi')
            return False
        else:
            self.puppet_desc_efi = lines[len(lines) - 5].strip()
            host_serial_handle.disconnect()
            log.info('EFI Shell: Puppet Description info: ' + self.puppet_desc_efi)
    else:
        log.error('Unable to boot to EFI')
        return False
    return True


class CommonSetup(Setup):
    '''
    Common Setup
    '''
    @aetest.subsection
    def connect(self, testscript, testbed_name):
        '''
        creates mandatory objects
        '''
        super(CommonSetup, self).connect(testscript, testbed_name)

    @aetest.subsection
    def initial_setup(self, cimc_util_obj, config):
        '''
        Initial Setups
        '''
        global classparam
        classparam['bios_obj'] = cimc_util_obj.bios_util_obj
        classparam['host_utils'] = HostUtils()
        classparam['boot_order_obj'] = BootOrder(cimc_util_obj, config)
        classparam['host_ip'] = get_host_mgmt_ip(config)

        # Disable SOL
        if cimc_util_obj.bios_util_obj.enable_disable_sol(value='no') is False:
            log.warning('Failed to set console redirect default values')
        if cimc_util_obj.bios_util_obj.console_redirect_defaults() is False:
            log.warning('Failed to set console redirect default values')

################# Common setup Ends ##############################################

        '''
        1. Chassis Asset tag reflect in all supported interface
        2. To check Chassis Asset tag after bios default method by both F9 key and manufacturing default
        3. Chassis Asset tag with Default setting
        4. Chassis Asset tag behavior after CIMC reboot and CIMC factory reset
        '''
################# Start of Testcase - verifyProcessorDetails #####################

# Logical ID: RACK-BIOS-Asset_tag -001/RACK-BIOS-IMC/ SMBIOS description -001
class AssestTagPuppetDescTest(aetest.Testcase):
    '''
        Verify Chassis Asset Tag Cross Check between CIMC ,UEFI shell and OS
    '''
    @aetest.setup
    def setup(self):
        '''
        Test Case Setup
        '''
        log.info("Setup Section verifyProcessorDetails")
        self.asset_tag_cli = None
        self.asset_tag_host = None
        self.asset_tag_efi = None
        self.puppet_desc_cli = None
        self.puppet_desc_host = None
        self.puppet_desc_efi = None

    @aetest.test
    def validate_assettag_puppet_desc_test(self, cimc_util_obj, config):
        '''
        Test Case Test Section
        '''
        boot_order_obj = classparam['boot_order_obj']

        # Fetch asset tag/puppet description from chassis cli
        if asset_tag_puppet_desc_cli(self, cimc_util_obj) is False:
            self.failed('Failed to get asset tag/description info from CLI', goto=['cleanup'])

        # Fetch asset tag/puppet description from host os
        if asset_tag_puppet_desc_host(self, config) is False:
            self.failed('Failed to get asset tag/puppet description info from Host', goto=['cleanup'])

        # Fetch asset tag/puppet description from efi shell
        if asset_tag_puppet_desc_efi(self, cimc_util_obj, boot_order_obj) is False:
            self.failed('Failed to get asset tag/puppet description from EFI', goto=['cleanup'])

        if self.asset_tag_cli == self.asset_tag_host == self.asset_tag_efi and \
                self.puppet_desc_cli == self.puppet_desc_host == self.puppet_desc_efi:
            self.passed('Successfully validated Asset Tag/Puppet description info across the interfaces')
        else:
            self.failed('Failed to validate Asset Tag/puppet description info across the interfaces' +
                        'Current Asset Tag info on different interface as below:' +
                        '\n AssetTag CLI: ' + self.asset_tag_cli + '\n Host: ' + self.asset_tag_host + '\n EFI: ' + self.asset_tag_efi +
                        '\n Puppet Desc CLI: ' + self.puppet_desc_cli + '\n Host: ' + self.puppet_desc_host + '\n EFI: ' + self.puppet_desc_efi)

    @aetest.cleanup
    def cleanup(self):
        '''
        Test Case Cleanup
        '''
        log.info('Cleanup section passed')
        boot_order_obj = classparam['boot_order_obj']
        # boot Host OS into HDD boot device
        if boot_order_obj.set_boot_order_HDD() is False:
            log.warning('Failed to into HDD boot device')


    # RACK-BIOS-Asset_tag -002 and RACK-BIOS-Asset_tag -003
    # RACK-BIOS-IMC/ SMBIOS description -002 and RACK-BIOS-IMC/ SMBIOS description -003
class AssestTagPuppetDescModifyTest(aetest.Testcase):
    '''
        Chassis Asset tag behavior after Bios load optimized Default setting and 
        Bios manufacturing default setting
    '''
    @aetest.setup
    def setup(self, cimc_util_obj):
        '''
        Test Case Setup
        '''
        log.info("Setup Section AssestTagModifyTest")
        self.asset_tag_cli = None
        self.asset_tag_host = None
        self.asset_tag_efi = None
        self.puppet_desc_cli = None
        self.puppet_desc_host = None
        self.puppet_desc_efi = None
        self.host_ip = classparam['host_ip']
        # Configure the user defined Asset Tag info
        self.usr_assettag = '\"Welcome To Rack-Automation\"'
        self.usr_validate_assettag = 'Welcome To Rack-Automation'

        self.usr_puppet_desc = '\"This is the test field for puppet description\"'
        self.usr_validate_puppet = 'This is the test field for puppet description'

        cimc_util_obj.handle.execute_cmd_list('top', 'scope chassis')
        cimc_util_obj.handle.execute_cmd('set asset-tag ' + self.usr_assettag)
        cimc_util_obj.handle.execute_cmd('set description ' + self.usr_puppet_desc)
        cimc_util_obj.handle.execute_cmd('commit')
        out = cimc_util_obj.handle.execute_cmd_list('top', 'scope chassis', 'show detail')
        res1 = re.search(r'asset-tag:\s+([^\r\n]+)', out)
        res2 = re.search(r'description:\s+([^\r\n]+)', out)
        if res1 is not None and res2 is not None:
            asset_tag = res1.group(1).strip()
            puppet_desc = res2.group(1).strip()
            if asset_tag == self.usr_validate_assettag and puppet_desc == self.usr_validate_puppet:
                log.info('Successfully set User defined Asset Tag and puppet description')
        else:
            self.failed('Failed to set user defined asset tag/puppet description info from CLI', goto=['cleanup'])

        # power cycle the host to reflect changes across all interfaces
        cimc_util_obj.power_cycle_host()
        cimc_util_obj.verify_host_up(hostname=self.host_ip, wait_for_ping_fail=False)

    bios_default_options = ['bios-setup-default', 'cimc-reboot']
    @aetest.test.loop(uids=['load_bios_default_test', 'cimc_reboot'],
                      parameter=bios_default_options)
    def test(self, cimc_util_obj, config, parameter):
        '''
        Test Case Test Section
        '''
        boot_order_obj = classparam['boot_order_obj']
        bios_obj = classparam['bios_obj']

        log.info("Verify Asset Tag Test Section")
        if parameter == 'bios-setup-default':
            if bios_obj.load_bios_defaults() is False:
                self.failed('Failed to do {} operation'.format(parameter))
        elif parameter == 'restore-mfg-defaults':
            if bios_obj.restore_tokens_to_defaults(parameter) is False:
                self.failed('Failed to do {} operation'.format(parameter))
        elif parameter == 'cimc-reboot':
            log.info('Performing reboot CIMC operation')
            res = cimc_util_obj.reboot_bmc_and_connect(config)
            if res is not True:
                self.failed('Failed to reboot and connect back', goto=['cleanup'])

        # Fetch asset tag/puppet description from chassis cli
        if asset_tag_puppet_desc_cli(self, cimc_util_obj) is False:
            self.failed('Failed to get asset tag/description info from CLI', goto=['cleanup'])

        # Fetch asset tag/puppet description from efi shell
        if asset_tag_puppet_desc_efi(self, cimc_util_obj, boot_order_obj) is False:
            self.failed('Failed to get asset tag/puppet description from EFI', goto=['cleanup'])

        # boot Host OS into HDD boot device
        if boot_order_obj.set_boot_order_HDD() is False:
            log.warning('Failed to into HDD boot device')

        # Fetch asset tag/puppet description from host os
        if asset_tag_puppet_desc_host(self, config) is False:
            self.failed('Failed to get asset tag/puppet description info from Host', goto=['cleanup'])

        if self.asset_tag_cli == self.asset_tag_host == self.asset_tag_efi and \
                self.puppet_desc_cli == self.puppet_desc_host == self.puppet_desc_efi:
            self.passed('Successfully validated Asset Tag/Puppet description info across the interfaces')
        else:
            self.failed('Failed to validate Asset Tag/puppet description info across the interfaces' +
                        'Current Asset Tag info on different interface as below:' +
                        '\n AssetTag CLI: ' + self.asset_tag_cli + '\n Host: ' + self.asset_tag_host + '\n EFI: ' + self.asset_tag_efi +
                        '\n Puppet Desc CLI: ' + self.puppet_desc_cli + '\n Host: ' + self.puppet_desc_host + '\n EFI: ' + self.puppet_desc_efi)

    @aetest.cleanup
    def cleanup(self):
        '''
        Test Case Cleanup
        '''
        log.info('Cleanup section passed')


class CommonCleanUp(Cleanup):
    ''' Common cleanup section'''
    @aetest.subsection
    def cleanup(self, cimc_util_obj):
        '''Cleanup'''
        super(CommonCleanUp, self).clean_everything(cimc_util_obj.handle)
