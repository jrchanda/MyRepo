'''
Created on Feb 21, 2017
@author: jchanda
'''
import logging
from ats import aetest
import common_utils
from common_test import Setup, Cleanup
from boot_order import BootOrder
from host_utils import HostUtils

log = logging.getLogger(__name__)

class CommonSetup(Setup):
    '''
    Common Setup section which connects to CIMC
    '''
    @aetest.subsection
    def connect(self, testscript, testbed_name):
        super(CommonSetup, self).connect(testscript, testbed_name)
class BasisBootOrderTest(aetest.Testcase):
    '''Basic Boot order setup'''
    @aetest.setup
    def setup(self, cimc_util_obj, config, con_obj):
        '''
        Setup method for all possible basic boot devices
        '''
        self.boot_order_obj = BootOrder(cimc_util_obj, config)
        self.host_handle = self.boot_order_obj.host_handle
        self.host_serial_handle = cimc_util_obj.telnet_handle
        self.host_util_obj = HostUtils(cimc_util_obj, config)
        self.config_obj = config.basic_boot_device_detail
        self.host_ip = common_utils.get_host_mgmt_ip(config)
        bios_obj = cimc_util_obj.bios_util_obj
        log.info('Display all basic boot order details:')
        for key in self.config_obj.keys():
            log.info(self.config_obj[key])
        # Disable SOL
        if bios_obj.enable_disable_sol(value='no') is False:
            log.warning('Failed to set console redirect default values')
        if bios_obj.console_redirect_defaults() is False:
            log.warning('Failed to set console redirect default values')
        aetest.loop.mark(
            self.verify_basic_boot_order,
            boot_device=self.config_obj.keys())
    @aetest.test
    def verify_basic_boot_order(self, cimc_util_obj, boot_device, con_obj):
        log.info('Configuring and testing of %s basic boot device' %(boot_device))
        basic_boot_dev_dict = {}
        options = con_obj.options(boot_device)
        for option in options:
            basic_boot_dev_dict[option] = con_obj.get(boot_device, option)
        log.info('Basic boot configure parameters:')
        log.info(basic_boot_dev_dict)
        log.info('Boot verify dictionary:')
        basic_boot_verify_dict = {k:v for k, v in (x.split(':') for x in basic_boot_dev_dict['verify'].split(','))}
        log.info(basic_boot_verify_dict)
        try:
            act_boot_device = basic_boot_dev_dict['act_device_type']
        except:
            act_boot_device = basic_boot_dev_dict['device_type']
        '''Create basic boot device '''
        res = self.boot_order_obj.create_basic_boot_order(boot_device, act_boot_device)
        if res is False:
            self.failed('Failed to create %s boot device' %(boot_device))
        cmd = basic_boot_verify_dict['cmd']
        if basic_boot_verify_dict['ssh_telnet'] == 'ssh':
            log.info('Validation: connecting host over SSH')
            cimc_util_obj.power_cycle_host()
            res1 = self.host_util_obj.check_file_on_host(self.host_handle, cmd)
        elif basic_boot_verify_dict['ssh_telnet'] == 'telnet':
            log.info('Validation: connecting host over telnet')
            self.host_serial_handle.connect_to_host_serial()
            cimc_util_obj.power_cycle_host()
            log.info('Waiting for host to boot into respective boot device')
            cimc_util_obj.verify_host_up(self.host_ip, wait_for_ping_fail=False, wait_time=500)
            res1 = self.host_serial_handle.check_file_on_console_host(cmd)
            self.host_serial_handle.disconnect()
        elif basic_boot_verify_dict['ssh_telnet'] == 'console_log':
            log.info('Validation: connecting host over serial and verify console logs')
            self.host_serial_handle.connect_to_host_serial()
            cimc_util_obj.power_cycle_host()
            log.info('Expected string is: ' + str(cmd.encode()))
            res1 = self.host_serial_handle.validate_host_console_output(exp_string=cmd.encode())
            self.host_serial_handle.disconnect()
        else:
            log.error('Invalid choice, please re-check testbed config file')
        '''Verify configured boot device and actual boot device should match '''
        log.info('verify the actual boot order after host reboot')
        res2 = self.boot_order_obj.verify_host_booted_from_configured_device(act_boot_device)
        if res1 is True and res2 is True:
            self.passed('Test Passed')
        else:
            self.failed('Test Failed')

class BootOrderTest(aetest.Testcase):
    '''Class to verify boot device for PXE/ISCSI/SDCARD/SAN/USB/VMEDIA/PCHSTORAGE/UEFISHELL/NVME'''
    @aetest.setup
    def setup(self, cimc_util_obj, config, con_obj):
        '''
        Setup method for all possible boot devices
        '''
        self.boot_order_obj = BootOrder(cimc_util_obj, config)
        self.host_handle = self.boot_order_obj.host_handle
        self.host_serial_handle = cimc_util_obj.telnet_handle
        self.host_util_obj = HostUtils(cimc_util_obj, config)
        bios_obj = cimc_util_obj.bios_util_obj
        self.config_obj = config.boot_device_detail
        log.info(self.config_obj)
        self.host_ip = common_utils.get_host_mgmt_ip(config)
        log.info('Display all boot order details:')
        for key in self.config_obj.keys():
            log.info(self.config_obj[key])
        boot_mode = con_obj.get('BootDeviceDetail', 'boot_mode')
        log.info('Testbed is configured in: ' + boot_mode)
        mode = self.boot_order_obj.get_boot_mode()
        log.info('Current configured boot mode: ' + mode)
        if mode != boot_mode:
            self.boot_order_obj.configure_boot_mode(boot_mode)
            cimc_util_obj.verify_host_up(self.host_ip)
        # Disable SOL
        if bios_obj.enable_disable_sol(value='no') is False:
            log.warning('Failed to set console redirect default values')
        if bios_obj.console_redirect_defaults() is False:
            log.warning('Failed to set console redirect default values')
        aetest.loop.mark(
            self.verify_boot_order,
            boot_device=self.config_obj.keys())
    @aetest.test
    def verify_boot_order(self, cimc_util_obj, boot_device, con_obj):
        '''Verify L2 boot order for all possible boot device configured on config file'''
        log.info('Running the test for boot device: ' + boot_device)
        log.info('Boot Configuration values are: ' + str(self.config_obj[boot_device]))
        boot_dev_dict = {}
        options = con_obj.options(boot_device)
        for option in options:
            boot_dev_dict[option] = con_obj.get(boot_device, option)
        log.info('Boot configure parameters:')
        log.info(boot_dev_dict)
        if boot_dev_dict['device_type'] == 'VMEDIA':
            res = self.boot_order_obj.check_vmedia_mapping(boot_dev_dict['device_sub_type'])
            if res  is not True:
                log.error('Failed to create VMEDIA mapping on the server for device: ')
        log.info('Remove boot device, if any created already')
        self.boot_order_obj.remove_boot_dev()
        '''Create boot and configure boot device'''
        res = self.boot_order_obj.create_and_configure_boot_device(boot_device, con_obj)
        if res is False:
            self.failed('Failed to create boot device for device type: ' + boot_device)
        elif res is 'SKIP':
            self.skipped('Boot device ' + boot_device + ' not configured on the testbed, Skipping test.')
        else:
            log.info('successfully created boot device for device type' + boot_device)
        log.info('Boot verify dictionary:')
        boot_verify_dict = {k:v for k, v in (x.split(':') for x in boot_dev_dict['verify'].split(','))}
        log.info(boot_verify_dict)
        cmd = boot_verify_dict['cmd']
        '''Power cycle host and verify whether host has booted to respective boot device'''
        if boot_verify_dict['ssh_telnet'] == 'ssh':
            log.info('Validation: connecting host over SSH')
            cimc_util_obj.power_cycle_host()
            res1 = self.host_util_obj.check_file_on_host(self.host_handle, cmd)
        elif boot_verify_dict['ssh_telnet'] == 'telnet':
            log.info('Validation: connecting host over telnet')
            self.host_serial_handle.connect_to_host_serial()
            cimc_util_obj.power_cycle_host()
            log.info('Waiting for host to boot into respective boot device')
            cimc_util_obj.verify_host_up(self.host_ip, wait_for_ping_fail=False, wait_time=500)
            res1 = self.host_serial_handle.check_file_on_console_host(cmd)
            self.host_serial_handle.disconnect()
        elif boot_verify_dict['ssh_telnet'] == 'console_log':
            log.info('Validation: connecting host over telnet and verify console logs')
            self.host_serial_handle.connect_to_host_serial()
            cimc_util_obj.power_cycle_host()
            log.info('Expected string is: ' + str(cmd.encode()))
            res1 = self.host_serial_handle.validate_host_console_output(exp_string=cmd.encode())
            self.host_serial_handle.disconnect()
        else:
            log.error('Invalid choice, please re-check testbed config file')
        '''Verify configured boot device and actual boot device should match '''
        try:
            act_boot_device = boot_dev_dict['act_device_type']
        except:
            act_boot_device = boot_dev_dict['device_type']
        log.info('verify the actual boot order after host reboot')
        res2 = self.boot_order_obj.verify_host_booted_from_configured_device(act_boot_device)
        if res1 is True and res2 is True:
            self.passed('Test Passed')
        else:
            self.failed('Test Failed')
    @aetest.test.loop(uids=['verify_boot_when_wrong_attr_set'], parameter=['HDD'])
    def verify_boot_when_wrong_attr_set(self, cimc_util_obj, config, parameter, con_obj):
        '''Verify boot device when wrong attribute set'''
        log.info('Verify that the host boots to the other available configured device \
                by setting the wrong attributes')
        boot_mode = con_obj.get('BootDeviceDetail', 'boot_mode')
        #if boot_mode != 'Legacy' or boot_mode != 'Uefi':
        #    self.skipped('Testbed is not configured to test this test, skipping test')
        boot_order_obj = BootOrder(cimc_util_obj, config)
        boot_device = 'myPXE'
        boot_dev_dict = {}
        try:
            options = con_obj.options(boot_device)
        except KeyError:
            self.skipped('PXE boot device not configured on testbed config file')
        for option in options:
            boot_dev_dict[option] = con_obj.get(boot_device, option)
        log.info('Boot configure parameters:')
        log.info(boot_dev_dict)
        boot_config_dict = {k:v for k, v in (x.split(':') for x in boot_dev_dict['config'].split(','))}
        slot_id = boot_config_dict['slot']
        port_id = boot_config_dict['port']
        log.info('Slot: %s and port: %s' % (slot_id, port_id))
        log.info(boot_config_dict)
        log.info('remove existing boot device if any')
        boot_order_obj.remove_boot_dev()
        log.info('create PXE boot device and enable the state, set order to 1, and wrong slot')
        if boot_order_obj.create_and_config_pxe_boot_device(slot_id, port_id, device_type='PXE', wrong_slot='MLOM') is False:
            self.failed('Failed to create PXE boot device')
        log.info('create LOCALHDD boot device and enable the state, set order to 2')
        if boot_order_obj.create_and_config_localhdd_boot_device(device_type=parameter, dev_order='2') is False:
            self.failed('Failed to create LOCALHDD boot device')
        log.info('Power cycle the host and verify that host boots into PXE boot device')
        boot_order_obj.powercycle_and_wait_for_host_comes_up()
        log.info('verify the actual boot order after host reboot')
        res1 = boot_order_obj.verify_host_booted_from_configured_device(device_type=parameter)
        if res1 is True:
            self.passed('Test Passed')
        else:
            self.failed('Test Failed')
    @aetest.test.loop(uids=['host_reboot', 'cimc_reboot', 'apc_cycle'], parameter=['host', 'cimc', 'apc_cycle'])
    def verify_last_boot_order_source_retain(self, cimc_util_obj, config, parameter, con_obj):
        '''Verify last boot order source'''
        log.info('To verify whether the last boot order source is retained on ' + parameter)
        boot_mode = con_obj.get('BootDeviceDetail', 'boot_mode')
        #if boot_mode != 'Legacy' or boot_mode != 'Uefi':
        #    self.skipped('Testbed is not configured to test this test, skipping test')
        boot_order_obj = BootOrder(cimc_util_obj, config)
        log.info('remove existing boot device if any')
        boot_order_obj.remove_boot_dev()
        log.info('create LOCALHDD boot device')
        boot_device = 'myLOCALHDD_RHEL'
        boot_dev_dict = {}
        try:
            options = con_obj.options(boot_device)
        except KeyError:
            self.skipped('LOCALHDD boot device not configured on this testbed')
        for option in options:
            boot_dev_dict[option] = con_obj.get(boot_device, option)
        log.info('Remove boot device, if any created already')
        boot_order_obj.remove_boot_dev()
        res = boot_order_obj.create_and_configure_boot_device(boot_device, con_obj)
        if res is False:
            self.failed('Failed to create boot device for device type: ' + boot_device)
        elif res is 'SKIP':
            self.skipped('Boot device ' + boot_device + ' not configured on the testbed, Skipping test.')
        else:
            log.info('successfully created boot device for device type' + boot_device)
        log.info('Reboot the respective component and check for last boot order source is retained ')
        if boot_order_obj.reboot_operations(parameter) is False:
            self.failed('Failed to power cycle the %s' % (parameter))
        res = boot_order_obj.last_update_config(exp_last_source='CIMC')
        if res is True:
            self.passed('Test Passed')
        else:
            self.failed('Test Failed')
class CommonCleanUp(Cleanup):
    ''' Common cleanup section'''
    @aetest.subsection
    def cleanup(self, cimc_util_obj):
        '''Cleanup'''
        super(CommonCleanUp, self).clean_everything(cimc_util_obj.handle)
