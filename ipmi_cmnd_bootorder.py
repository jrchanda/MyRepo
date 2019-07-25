'''
__author__ = 'Jagadish Chanda <jchanda@cisco.com>'
__copyright__ = 'Copyright 2017, Cisco Systems'
__email__ = 'jchanda@cisco.com'
__date__ = 'Oct 13,2017'
__version__ = 1.0
'''
# Needed for aetest script
import logging
import subprocess

from ats import aetest

from common_utils import dump_error_in_lib, get_host_mgmt_ip
from common_test import Setup, Cleanup
from host_utils import HostUtils
from boot_order import BootOrder
from storage_utils import StorageUtils

################################################################################
# Global class variable to maintain objects by creating one time and
# use all over the script
################################################################################
classparam = {}

# Get your logger for your script
log = logging.getLogger(__name__)


def configure_boot_device_ipmi(config, bootdev=None, options=None):
    '''
    Procedure to configure boot deivce using IPMI commands
    Parameter:
        bootdev : name of the boot device(cdrom, disk, bios, floppy, pxe)
        options: <optionsal> when passed, then consistent boot device will be created
    Return:
        True  : Success
        False : Failure
    '''
    log.info('configure_boot_device_ipmi: will execute the ipmi command')
    ipmicmd = '/data/home/releng/rm_automation/bin/ipmitool_RH_64bit_06012015'
    mgmt_detail_obj = config.mgmtdetail
    bmc_ip = mgmt_detail_obj.bmc_mgmt_ip
    bmc_login = mgmt_detail_obj.bmc_login
    bmc_passwd = mgmt_detail_obj.bmc_password

    cmdstr = ipmicmd + ' -H ' + bmc_ip + ' -I lanplus' + ' -U ' + bmc_login + ' -P ' + bmc_passwd + ' chassis'
    if bootdev is not None:
        cmdstr += ' bootdev ' + bootdev
    if options is not None:
        cmdstr += ' options=' + options

    log.info('Formated command is: ' + cmdstr)
    try:
        cmd_out = subprocess.check_output(cmdstr, shell=True, stderr=subprocess.STDOUT)
        log.info('command output: ' + str(cmd_out))
        return cmd_out.strip().decode()
    except:
        log.error('Failed to execute the cmd: ' + str(cmdstr))
        dump_error_in_lib()
        return False

    # To make sure that, persistent device boot option which was set from previous commands
    # will be deleted with below piece of code.
def remove_consistent_ipmi_boot(cimc_util_obj, config):
    '''
    Procedure to remove consistent device boot option
    '''
    bootdev = 'bios'
    validation_str = 'Main'
    expected_output = 'Set Boot Device to '
    cmd_out = configure_boot_device_ipmi(config, bootdev)
    if cmd_out == expected_output + bootdev:
        log.info('Successfully executed, and got expected output: ' + str(cmd_out))
    else:
        log.error('Failed to get expected command output. Expected was %s, but got as %s'
                  % (expected_output + bootdev, cmd_out))
    cimc_util_obj.power_cycle_host()
    log.info('Expected string is: ' + str(validation_str.encode()))
    res = cimc_util_obj.telnet_handle.validate_host_console_output(exp_string=validation_str.encode())
    if res == 'Fail':
        log.error('Failed to set non-persistent boot order for boot device %s' % (bootdev))

################# Common setup Starts ############################################


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
    def initial_setup(self, cimc_util_obj, config, con_obj):
        '''
        Initial Setups
        '''
        global classparam
        classparam['boot_order_obj'] = BootOrder(cimc_util_obj)
        classparam['host_utils'] = HostUtils()
        classparam['host_ip'] = get_host_mgmt_ip(config)
        classparam['host_serial_handle'] = cimc_util_obj.telnet_handle
        classparam['storage_util_obj'] = StorageUtils(cimc_util_obj)

        mgmt_detail_obj = config.mgmtdetail
        classparam['bmc_ip'] = mgmt_detail_obj.bmc_mgmt_ip
        classparam['bmc_login'] = mgmt_detail_obj.bmc_login
        classparam['bmc_passwd'] = mgmt_detail_obj.bmc_password
        classparam['ipmicmd'] = '/data/home/releng/rm_automation/bin/ipmitool_RH_64bit_06012015'

        # defining validation strings
        classparam['validation_string'] = {'bios': 'Main',
                                           'pxe': 'DHCP.',
                                           'disk': 'login',
                                           'floppy': r'A:\>',
                                           'cdrom': 'ISOLINUX'
                                          }
        # Expected output string of IPMI command
        classparam['expected_out'] = 'Set Boot Device to '

        # Will be testing ipmi command bootorder test cases in Legacy mode setup.
        # Configure the testbed to Legacy if not already set.
        boot_order_obj = classparam['boot_order_obj']

        # Get the VD no where legacy mode setup OS VD installed
        legacy_boot_vd = con_obj.get('BootDeviceDetail', 'legacy_vd')
        res = classparam['storage_util_obj'].configure_boot_vd(legacy_boot_vd)
        if res is False:
            self.failed('Failed to set VD %s as boot VD' %(legacy_boot_vd))
        else:
            log.info('successfully set VD %s as boot VD' %(legacy_boot_vd))
        mode = boot_order_obj.get_boot_mode()
        log.info('Current configured boot mode: ' + mode)
        boot_mode = 'Legacy'
        if mode != boot_mode:
            boot_order_obj.configure_boot_mode(boot_mode)
            cimc_util_obj.verify_host_up(classparam['host_ip'])
################# Common setup Ends ##############################################


################# Start of Testcase - verifyProcessorDetails #####################
class NonPersistentBootDevice(aetest.Testcase):
    '''
    Configure boot device to boot to bios, pxe, hdd, cdrom, floppy in non-persistent mode using IPMI
    '''
    @aetest.setup
    def setup(self):
        '''
        Test Case Setup
        '''
        log.info("Setup Section verifyProcessorDetails")
        self.host_serial_handle = classparam['host_serial_handle']
        self.host_serial_handle.connect_to_host_serial()

    '''
    ipmi_001, ipmi_002, ipmi_004, ipmi_005, ipmi_007, ipmi_009
    '''
    @aetest.test.loop(uids=['bios_setup_boot', 'pxe_boot', 'hdd_boot', 'boot_floppy', 'boot_cdrom'],
                      parameter=['bios', 'pxe', 'disk', 'floppy', 'cdrom'])
    def test(self, cimc_util_obj, config, parameter):
        '''
        ipmi command to set boot to bios, pxe, hdd, cdrom, floppy drive options in non-persistent mode
        '''
        # Run the ipmi command with boot order
        expected_out = classparam['expected_out']
        validation_string = classparam['validation_string']
        bootdev = parameter
        cmd_out = configure_boot_device_ipmi(config, bootdev)
        if cmd_out == expected_out + bootdev:
            log.info('Successfully executed, and got expected output: ' + str(cmd_out))
        else:
            log.error('Failed to get expected command output. Expected was %s, but got as %s'
                      % (expected_out + bootdev, cmd_out))

        # Power cycle the host and verify host boot
        log.info('Validation: connecting host over telnet and verify console logs')

        cimc_util_obj.power_cycle_host()
        cmd = validation_string[parameter]
        log.info('Expected string is: ' + str(cmd.encode()))
        result = self.host_serial_handle.validate_host_console_output(exp_string=cmd.encode())
        if result == 'Fail':
            self.failed('Failed to validate persistent boot using ipmi for boot device %s' % (bootdev))
        else:
            self.passed('Successfully validated persistent boot using ipmi for boot device %s' % (bootdev))

    @aetest.cleanup
    def cleanup(self):
        '''
        Test Case Cleanup
        '''
        # disconnect host serial handle
        self.host_serial_handle.disconnect()
        log.info('Cleanup section passed')


class PersistentBootDevice(aetest.Testcase):
    '''
    Configure boot device to boot to bios, pxe, hdd, cdrom, floppy drive options in persistent mode using IPMI
    '''
    @aetest.setup
    def setup(self):
        '''
        Test Case Setup
        '''
        log.info("Setup Section verifyProcessorDetails")
        self.host_serial_handle = classparam['host_serial_handle']
        self.host_serial_handle.connect_to_host_serial()

    '''
    ipmi_003, ipmi_006, ipmi_008, ipmi_010    
    '''
    @aetest.test.loop(uids=['bios_setup_boot', 'pxe_boot', 'hdd_boot', 'boot_floppy', 'boot_cdrom'],
                      parameter=['bios', 'pxe', 'disk', 'floppy', 'cdrom'])
    def test(self, cimc_util_obj, config, parameter):
        '''
        ipmi command to set boot to bios, pxe, hdd, cdrom, floppy drive options in persistent mode
        '''
        # Run the ipmi command with boot order
        expected_out = classparam['expected_out']
        validation_string = classparam['validation_string']
        bootdev = parameter
        options = 'persistent'
        cmd_out = configure_boot_device_ipmi(config, bootdev, options)
        if cmd_out == expected_out + bootdev:
            log.info('Successfully executed, and got expected output: ' + str(cmd_out))
        else:
            log.error('Failed to get expected command output. Expected was %s, but got as %s'
                      % (expected_out + bootdev, cmd_out))

        # Power cycle the host and verify host boot
        log.info('Validation: connecting host over telnet and verify console logs')
        # 1st host reboot
        log.info('1st Host reboot: Verify that host boots to expected boot device %s' % (parameter))
        cimc_util_obj.power_cycle_host()
        cmd = validation_string[parameter]
        log.info('Expected string is: ' + str(cmd.encode()))
        result = self.host_serial_handle.validate_host_console_output(exp_string=cmd.encode())
        if result == 'Fail':
            self.failed('Failed to validate persistent boot order for boot device %s' % (parameter))

        # 2nd host reboot
        log.info('2nd Host Reboot: Verify that host boots again to previously booted boot device %s' % (parameter))
        cimc_util_obj.power_cycle_host()
        cmd = validation_string[parameter]
        log.info('Expected string is: ' + str(cmd.encode()))
        result2 = self.host_serial_handle.validate_host_console_output(exp_string=cmd.encode())
        if result2 == 'Fail':
            self.failed('Failed to validate persistent boot order for boot device %s' % (parameter))

        self.passed('Successfully validated persistent ipmi boot order for boot device %s' % (parameter))

    @aetest.cleanup
    def cleanup(self, cimc_util_obj, config):
        '''
        Test Case Cleanup
        '''
        # disconnect host serial handle
        self.host_serial_handle.disconnect()
        # delete persistent device boot option
        remove_consistent_ipmi_boot(cimc_util_obj, config)
        log.info('Cleanup section passed')


class CimcConfigIPMICmdNonPersistentBootDevice(aetest.Testcase):
    '''
    Configure boot device to bios, pxe, hdd, cdrom, floppy drive options in non persistent mode
    when boot device set from CIMC config and booted from it
    '''
    @aetest.setup
    def setup(self, cimc_util_obj):
        '''
        Test Case Setup
        '''
        log.info("Setup Section verifyProcessorDetails")
        host_ip = classparam['host_ip']
        boot_order_obj = classparam['boot_order_obj']

        self.host_serial_handle = classparam['host_serial_handle']
        self.host_serial_handle.connect_to_host_serial()

        # Create boot device from CIMC config and boot from it.
        log.info('Create boot device from CIMC config and boot from it')
        if boot_order_obj.create_and_config_localhdd_boot_device('HDD') is False:
            self.failed('Failed to create boot device from CIMC')
        log.info('Waiting for host to boot into respective boot device')
        cimc_util_obj.power_cycle_host()
        res = cimc_util_obj.verify_host_up(hostname=host_ip, wait_for_ping_fail=False)
        if res is False:
            log.error('Failed to boot from cimc configured boot device')
        else:
            log.info('Successfully booted from cimc configured boot device')
    '''
    ipmi_014, ipmi_015, ipmi_017, ipmi_019
    '''
    @aetest.test.loop(uids=['bios_setup_boot', 'pxe_boot', 'hdd_boot', 'boot_floppy', 'boot_cdrom'],
                      parameter=['bios', 'pxe', 'disk', 'floppy', 'cdrom'])
    def test(self, cimc_util_obj, config, parameter):
        '''
        ipmi command to set boot to bios, pxe, hdd, cdrom, floppy drive options in non-persistent mode
        '''
        expected_out = classparam['expected_out']
        validation_string = classparam['validation_string']
        # Run the ipmi command with boot order
        bootdev = parameter
        options = 'persistent'
        cmd_out = configure_boot_device_ipmi(config, bootdev, options)
        if cmd_out == expected_out + bootdev:
            log.info('Successfully executed, and got expected output: ' + str(cmd_out))
        else:
            log.error('Failed to get expected command output. Expected was %s, but got as %s'
                      % (expected_out + bootdev, cmd_out))

        # Power cycle the host and verify host boot
        log.info('Validation: connecting host over telnet and verify console logs')
        log.info('Verify that host boots to expected boot device %s' % (parameter))
        cimc_util_obj.power_cycle_host()
        cmd = validation_string[parameter]
        log.info('Expected string is: ' + str(cmd.encode()))
        result = self.host_serial_handle.validate_host_console_output(exp_string=cmd.encode())
        if result == 'Fail':
            self.failed('Failed to validate non-persistent boot for boot device %s' % (parameter))

    @aetest.cleanup
    def cleanup(self, cimc_util_obj, config):
        '''
        Test Case Cleanup
        '''
        expected_out = classparam['expected_out']
        validation_string = classparam['validation_string']
        # disconnect host serial handle
        self.host_serial_handle.disconnect()
        # delete persistent device boot option
        remove_consistent_ipmi_boot(cimc_util_obj, config)
        log.info('Cleanup section passed')

class CimcConfigIPMICmdPersistentBootDevice(aetest.Testcase):
    '''
    Configure boot device to bios, pxe, hdd, cdrom, floppy in persistent mode
    when boot device created using cimc config and booted from it
    '''
    @aetest.setup
    def setup(self, cimc_util_obj):
        '''
        Test Case Setup
        '''
        log.info("Setup Section verifyProcessorDetails")
        host_ip = classparam['host_ip']
        boot_order_obj = classparam['boot_order_obj']

        self.host_serial_handle = classparam['host_serial_handle']
        self.host_serial_handle.connect_to_host_serial()

        # Create boot device from CIMC config and boot from it.
        log.info('Create boot device from CIMC config and boot from it')
        if boot_order_obj.create_and_config_localhdd_boot_device('HDD') is False:
            self.failed('Failed to create boot device from CIMC')
        log.info('Waiting for host to boot into respective boot device')
        cimc_util_obj.power_cycle_host()
        res = cimc_util_obj.verify_host_up(hostname=host_ip, wait_for_ping_fail=False)
        if res is False:
            self.failed('Failed to boot from cimc configured boot device')
        else:
            log.info('Successfully booted from cimc configured boot device')
    '''
    ipmi_013, ipmi_016, ipmi_018, ipmi_020
    '''
    @aetest.test.loop(uids=['bios_setup_boot', 'pxe_boot', 'hdd_boot', 'boot_floppy', 'boot_cdrom'],
                      parameter=['bios', 'pxe', 'disk', 'floppy', 'cdrom'])
    def test(self, cimc_util_obj, config, parameter):
        '''
        ipmi command to set boot to bios, pxe, hdd, cdrom, floppy drive options in persistent mode
        when cimc config set and booted from it
        '''
        expected_out = classparam['expected_out']
        validation_string = classparam['validation_string']
        # Run the ipmi command with boot order
        bootdev = parameter
        options = 'persistent'
        cmd_out = configure_boot_device_ipmi(config, bootdev, options)
        if cmd_out == expected_out + bootdev:
            log.info('Successfully executed, and got expected output: ' + str(cmd_out))
        else:
            log.error('Failed to get expected command output. Expected was %s, but got as %s'
                      % (expected_out + bootdev, cmd_out))

        # Power cycle the host and verify host boot
        log.info('Validation: connecting host over telnet and verify console logs')
        # 1st host reboot
        log.info('1st Host reboot: Verify that host boots to expected boot device %s' % (parameter))
        cimc_util_obj.power_cycle_host()
        cmd = validation_string[parameter]
        log.info('Expected string is: ' + str(cmd.encode()))
        result = self.host_serial_handle.validate_host_console_output(exp_string=cmd.encode())
        if result == 'Fail':
            self.failed('Failed to validate persistent boot for boot device %s' % (parameter))

        # 2nd host reboot
        log.info('2nd Host Reboot: Verify that host boots again to previously booted boot device %s' % (parameter))
        cimc_util_obj.power_cycle_host()
        cmd = validation_string[parameter]
        log.info('Expected string is: ' + str(cmd.encode()))
        result2 = self.host_serial_handle.validate_host_console_output(exp_string=cmd.encode())
        if result2 == 'Fail':
            self.failed('Failed to validate persistent boot for boot device %s' % (parameter))

        self.passed('Successfully validated persistent ipmi boot for boot device %s' % (parameter))

    @aetest.cleanup
    def cleanup(self, cimc_util_obj, config):
        '''
        Test Case Cleanup
        '''
        # disconnect host serial handle
        self.host_serial_handle.disconnect()
        # delete persistent device boot option
        remove_consistent_ipmi_boot(cimc_util_obj, config)
        log.info('Cleanup section passed')

class CommonCleanUp(Cleanup):
    ''' Common cleanup section'''
    @aetest.subsection
    def cleanup(self, cimc_util_obj, con_obj):
        '''Cleanup'''
        # Boot system back to UEFI mode
        boot_order_obj = classparam['boot_order_obj']

        # Get the VD no where legacy mode setup OS VD installed
        uefi_boot_vd = con_obj.get('BootDeviceDetail', 'uefi_vd')
        expected_boot_mode = 'Uefi'
        mode = boot_order_obj.get_boot_mode()
        log.info('Current configured boot mode: ' + mode)
        if mode != expected_boot_mode:
            # configure boot vd
            res = classparam['storage_util_obj'].configure_boot_vd(uefi_boot_vd)
            if res is False:
                log.error('Failed to set VD/PD as boot VD/PD')
            cimc_util_obj.verify_host_up(classparam['host_ip'], wait_for_ping_fail=False)

        super(CommonCleanUp, self).clean_everything(cimc_util_obj.handle)
