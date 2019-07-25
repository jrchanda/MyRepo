'''
Created on July 28, 2017
@author: jchanda
'''
import logging
import subprocess
import re

from ats import aetest

import common_utils
from boot_order import BootOrder
from SystemDetailsCollector_lib import SystemDetailsCapture
from storage_utils import StorageUtils
from common_test import Setup, Cleanup
from host_utils import HostUtils


def pcie_config_details(config):
    '''
    Procedure will return PCIe inventory details in dictionary format
    '''
    # Parse testbed config file and create pcie adapter dict => {slotID:product_name}
    pcie_config_dict = {}
    pcie_list = config.pci_adapter_detail
    for pcie in pcie_list:
        log.info('Adapter slot:' + pcie.slot)
        log.info('Adapter Product Name:' + pcie.product_name)
        pcie_config_dict[pcie.slot] = pcie.product_name

    log.info('PCI Adapter details present in the dictionary')
    log.info(pcie_config_dict)
    return pcie_config_dict

################################################################################
# Global class variable to maintain objects by creating one time and
# use all over the script
################################################################################
classparam = {}

# Get your logger for your script
log = logging.getLogger(__name__)


class CommonSetup(Setup):
    '''
    Common Setup section which connects to CIMC
    '''
    @aetest.subsection
    def connect(self, testscript, testbed_name):
        super(CommonSetup, self).connect(testscript, testbed_name)

    @aetest.subsection
    def inital_setup(self, cimc_util_obj, config):
        global system_capture_object
        system_capture_object = SystemDetailsCapture(cimc_util_obj, config)

        global classparam
        classparam['boot_order_obj'] = BootOrder(cimc_util_obj)
        classparam['host_util_obj'] = HostUtils(cimc_util_obj, config)
        classparam['storage_util_obj'] = StorageUtils(cimc_util_obj, config)

class PcieExpressCardTest(aetest.Testcase):
    '''
    To verify the populated PCI express card is detected on CIMC, OS are correct
    and should match to the PCI inventory mentioned on config data file
    Logical ID: RACK-BIOS-DN-PCI-E Generic Test Cases-001
                RACK-BIOS-DN-PCI-E Generic Test Cases-002
    '''

    @aetest.setup
    def pci_setup(self, cimc_util_obj, config):
        '''
        Setup method for all possible variables and object initializations
        '''
        self.pcie_config_dict = pcie_config_details(config)
        log.info('PCI Adapter details present in the dictionary')
        log.info(self.pcie_config_dict)

        self.host_ip = common_utils.get_host_mgmt_ip(config)
        self.mgmt_handle = cimc_util_obj.handle

    @aetest.test
    def pcie_test(self):
        '''
        PCIe inventory test section
        '''
        log.info('Test section started, PCI Express inventory')
        boot_order_obj = classparam['boot_order_obj']
        host_util_obj = classparam['host_util_obj']

        log.info('Connect to host and get the PCI inventory using dmidecoe -t 202 command')
        cmd = 'dmidecode -t 202'
        host_output = host_util_obj.connect_host_and_execute_command(cmd, boot_order_obj)
        # Parse output file and create dict of {slotID:product_name}
        host_pci_dict = {}
        reg = re.compile(r'Strings:.*\W+(.*\W)(.*\W)')
        for line in reg.findall(host_output):
            host_pci_dict[line[1].strip().split(':')[1]] = line[0].strip()
        log.info('PCI Adapter inventory from host OS:')
        log.info(host_pci_dict)

        # Get the PCI adapter inventory from CIMC CLI and create dict of {slotID:product_name}
        cli_pci_dict = {}
        cli_out = self.mgmt_handle.execute_cmd_list('top', 'scope chassis', 'show pci-adapter detail')
        for block in cli_out.split('---')[1:]:
            slot_id = re.search('slot:[ \t+]([^\r\n]+)', block).group(1)
            product_name = re.search('product-name:[ \t+]([^\r\n]+)', block).group(1)
            cli_pci_dict[slot_id] = product_name
        log.info('PCI Adapter inventory from CIMC CLI:')
        log.info(cli_pci_dict)

        res1 = common_utils.compare_dictionaries(self.pcie_config_dict, host_pci_dict)
        res2 = common_utils.compare_dictionaries(self.pcie_config_dict, cli_pci_dict)

        if res1 is True and res2 is True:
            self.passed('Test Passed')
        else:
            log.error('PCIE Adapter details are not matched between populated on the system and \
            config file')
            log.info('PCIE Adapter Inventory from config file: ' + str(self.pcie_config_dict))
            log.info('PCIE Adapter Inventory from Host config file: ' + str(host_pci_dict))
            log.info('PCIE Adapter Inventory from CIMC CLI: ' + str(cli_pci_dict))
            self.failed('Test Failed')

    @aetest.cleanup
    def pcie_cleanup(self):
        '''
        PCIe inventory cleanup section
        '''
        log.info('Terminated the host serial console session')


class HuuUpdateTest(aetest.Testcase):
    '''
    HUU Update setup
    Logical ID: RACK-BIOS-DN-PCI-E Generic Test Cases-009
                RACK-BIOS-DN-PCI-E Generic Test Cases-010
    '''
    @aetest.setup
    def setup(self, cimc_util_obj, config):
        '''
        Setup method for all possible variables and object initializations
        '''
        log.info('setup test case')
        self.pcie_config_dict = pcie_config_details(config)
        log.info(self.pcie_config_dict)

        self.host_ip = common_utils.get_host_mgmt_ip(config)
        self.mgmt_handle = cimc_util_obj.handle
        # clear the SEL logs
        log.info('Clearing the SEL logs')
        cimc_util_obj.clear_cimc_sel_logs(log_scope='sel')
        log.info('setup section passed')

    @aetest.test
    def test(self, cimc_util_obj, huu_update_info):
        log.info('Test section started')

        host_util_obj = classparam['host_util_obj']
        boot_order_obj = classparam['boot_order_obj']

        '''node=1, release='granite_peak', version='ucs-c240m5-huu-3.1.1S3.iso'''
        # Collect the SEL logs before proceeding for HUU Update
        sel_log_before = cimc_util_obj.get_cimc_sel_log_latest_event(
            log_scope='sel')
        log.info('SEL log latest event is: ' + sel_log_before)
        # HUU Update
        res = cimc_util_obj.HuuUpdate(huu_update_info)
        if res is False:
            self.failed('Failed to update HUU, test failed')

        log.info('Collecting SEL logs after event and check for critical events')
        sel_log_flag = cimc_util_obj.check_cimc_sel_log_diff_event(sel_log_before, log_scope='sel')
        log.info('Result of SEL log is: ' + str(sel_log_flag))

        log.info('Connect to host and get the PCI inventory using dmidecoe -t 202 command')
        cmd = 'dmidecode -t 202'
        host_output = host_util_obj.connect_host_and_execute_command(cmd, boot_order_obj)
        # Parse output file and create dict of {slotID:product_name}
        host_pci_dict = {}
        reg = re.compile(r'Strings:.*\W+(.*\W)(.*\W)')
        for line in reg.findall(host_output):
            host_pci_dict[line[1].strip().split(':')[1]] = line[0].strip()
        log.info('PCI Adapter inventory from host OS:')
        log.info(host_pci_dict)

        # Get the PCI adapter inventory from CIMC CLI and create dict of {slotID:product_name}
        cli_pci_dict = {}
        cli_out = self.mgmt_handle.execute_cmd_list('top', 'scope chassis', 'show pci-adapter detail')
        for block in cli_out.split('---')[1:]:
            slot_id = re.search('slot:[ \t+]([^\r\n]+)', block).group(1)
            product_name = re.search('product-name:[ \t+]([^\r\n]+)', block).group(1)
            cli_pci_dict[slot_id] = product_name
        log.info('PCI Adapter inventory from CIMC CLI:')
        log.info(cli_pci_dict)

        res1 = common_utils.compare_dictionaries(self.pcie_config_dict, host_pci_dict)
        res2 = common_utils.compare_dictionaries(self.pcie_config_dict, cli_pci_dict)
        log.info('Result of res1=%s and res2=%s' % (res1, res2))

        fail_flag = 0
        if res1 is True and res2 is True:
            log.info('successfully validated PCIe inventory after the update')
            self.passed('Test Passed')
        else:
            log.error('PCIE Adapter details are not matched between populated on the system and \
            config file aftert HUU update')
            log.info('PCIE Adapter Inventory from config file: ' + str(self.pcie_config_dict))
            log.info('PCIE Adapter Inventory from Host config file: ' + str(host_pci_dict))
            log.info('PCIE Adapter Inventory from CIMC CLI: ' + str(cli_pci_dict))
            fail_flag = 1

        if sel_log_flag is True:
            log.info('No unexpected events found in log')
        else:
            log.error('Found not expected events in log')
            fail_flag = 1

        if fail_flag == 1:
            self.failed('Test Failed')
        else:
            self.passed('Test Passed')

    @aetest.cleanup
    def cleanup(self):
        '''
        HuuUpdateTest cleanup section
        '''
        log.info('Cleanup section passed')


class PcieLegacyModeTest(aetest.Testcase):
    '''
    Logical ID: RACK-BIOS-DN-PCI-E Generic Test Cases-003
    '''

    @aetest.setup
    def setup(self, cimc_util_obj, config, con_obj):
        '''
        Setup method for all possible variables and object initializations
        '''
        log.info('setup section')
        host_util_obj = classparam['host_util_obj']
        boot_order_obj = classparam['boot_order_obj']
        storage_util_obj = classparam['storage_util_obj']

        self.host_ip = common_utils.get_host_mgmt_ip(config)
        self.mgmt_handle = cimc_util_obj.handle
        self.host_serial_handle = cimc_util_obj.telnet_handle

        self.pcie_config_dict = pcie_config_details(config)
        log.info(self.pcie_config_dict)

        boot_mode = con_obj.get('BootDeviceDetail', 'boot_mode')
        log.info('Testbed is configured in: ' + boot_mode)

        self.uefi_vd_no = con_obj.get('BootDeviceDetail', 'uefi_vd')
        log.info('UEFI VD no: ' + str(self.uefi_vd_no))

        legacy_vd_no = con_obj.get('BootDeviceDetail', 'legacy_vd')
        log.info('Legacy VD no: ' + str(legacy_vd_no))

        expected_boot_mode = 'Legacy'
        mode = boot_order_obj.get_boot_mode()
        log.info('Current configured boot mode: ' + mode)
        if mode != expected_boot_mode:
            # configure boot vd
            res = storage_util_obj.configure_boot_vd(legacy_vd_no)
            if res is False:
                self.failed('Failed to set VD/PD as boot VD/PD')
            # configure to Legacy mode
            boot_order_obj.configure_boot_mode(expected_boot_mode)
            cimc_util_obj.verify_host_up(self.host_ip, wait_for_ping_fail=False)

    @aetest.test
    def test(self, cimc_util_obj):
        log.info('Test section')
        results = 'Pass'
        telnet_handle = cimc_util_obj.telnet_handle
        log.info('Verify the connected PCI express card is dispatching its OPROM during POST')

        # connect to host serial session
        log.info('Validation: connecting host over telnet and verify console logs')
        host_serial_handle = cimc_util_obj.telnet_handle
        host_serial_handle.connect_to_host_serial()
        cimc_util_obj.power_cycle_host()

        #exp_str = 'boot Agent'
        exp_str = 'boot'
        res = host_serial_handle.validate_host_console_output(exp_string=exp_str.encode())
        host_serial_handle.disconnect()

        if res is True:
            log.info('Successfully validated the OPROM messages for LOM port')
            self.passed('Test Passed')
        else:
            log.error('Failed to validate OPROM messages for LOM port')
            self.failed('Test Failed')

    @aetest.cleanup
    def cleanup(self, cimc_util_obj):
        log.info('Cleanup section')
        boot_order_obj = classparam['boot_order_obj']
        storage_util_obj = classparam['storage_util_obj']

        expected_boot_mode = 'Uefi'
        mode = boot_order_obj.get_boot_mode()
        log.info('Current configured boot mode: ' + mode)
        if mode != expected_boot_mode:
            # configure boot vd
            res = storage_util_obj.configure_boot_vd(self.uefi_vd_no)
            if res is False:
                self.failed('Failed to set VD/PD as boot VD/PD')
            boot_order_obj.configure_boot_mode(expected_boot_mode)
            cimc_util_obj.verify_host_up(self.host_ip, wait_for_ping_fail=False)


class CommonCleanUp(Cleanup):
    ''' Common cleanup section'''
    @aetest.subsection
    def cleanup(self, cimc_util_obj):
        '''Cleanup'''
        super(CommonCleanUp, self).clean_everything(cimc_util_obj.handle)
