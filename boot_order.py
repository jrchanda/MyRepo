'''
Created on Feb 21, 2017
@author: jchanda
'''
import logging
import time
import re
import common_utils
from common_utils import dump_error_in_lib
from host_utils import HostUtils
from storage_utils import StorageUtils

log = logging.getLogger(__name__)

__author__ = 'Jagadish Chanda <jchanda@cisco.com>'
__copyright__ = 'Copyright 2016, Cisco Systems'
__email__ = 'jchanda@cisco.com'
__date__ = 'Jan 12,2016'
__version__ = 1.0

class ActBootOrderDetails():
    '''
    Holding actual boot order details
    '''

    def __init__(self, order, device_name, device_type=None, rn=None, slot=None, lun=None, sub_type=None):
        self.order = order
        self.device_name = device_name
        self.device_type = device_type
        self.rn = rn
        self.slot = slot
        self.lun = lun
        self.sub_type = sub_type


class BootOrder():
    '''
        Library for boot order related functions which include configuring boot-order
        set actual boot order, boot from default boot device. etc
    '''

    def __init__(self, cimc_utils_obj, config=None):
        self.cimc_utils_obj = cimc_utils_obj
        self.mgmt_handle = cimc_utils_obj.handle
        self.host_handle = cimc_utils_obj.host_handle
        self.telnet_handle = cimc_utils_obj.telnet_handle
        self.config = config
        self.actual_boot_order = None
        self.actual_boot_order_dict = {}
        self.device_type_arr = []
        self.get_actual_boot_dev_info()
        self.get_boot_mode()
        self.host_util_obj = HostUtils(config)
        self.storage_util_obj = StorageUtils(cimc_utils_obj, config)
    def get_boot_mode(self):
        '''
        Procedure to get configured boot mode
        Parameter:
             None
        Return:
            Uefi : If configured in uefi mode
            Legacy : If configured in legacy mode
        Author: jchanda
        '''
        out = self.mgmt_handle.execute_cmd_list('top', 'scope bios', 'show detail')
        boot_mode = None
        value = re.search('act-boot-mode:\s+([^\r\n]+)', out)
        if value != None:
            value = value.group(1)
            if value == 'Uefi':
                boot_mode = 'Uefi'
            elif value == 'Legacy':
                boot_mode = 'Legacy'
        else:
            log.warning('Failed to get Actual boot mode')
        self.boot_mode = boot_mode
        return boot_mode
    def configure_boot_mode(self, mode):
        '''
        Procedure to configure boot mode
        Parameter:
             Boot option: Legacy Mode
                          Uefi Mode
        Return:
            True : Success
            False : Failure
        Author: jchanda
        '''
        self.mgmt_handle.execute_cmd_list('top', 'scope bios', 'set boot-mode ' + mode)
        out = self.mgmt_handle.execute_cmd('commit', wait_time=10)
        try:
            if 'Do you want to reboot the system' in out:
                self.mgmt_handle.execute_cmd('y')
        except:
            dump_error_in_lib()
            return False
    def last_update_config(self, exp_last_source='CIMC'):
        '''Procedure to check last update config'''
        log.info('Verify last boot order source')
        out = self.mgmt_handle.execute_cmd_list('top', 'scope bios', 'show detail')
        last_upd_cfg = re.search(r'last-upd-cfg:\s+([^\r\n]+)', out).group(1)
        if last_upd_cfg == exp_last_source:
            log.info('Last boot order source changed from is ' + last_upd_cfg)
            return True
        else:
            log.error('Last boot order source is from %s, but expected was %s' 
                      (last_upd_cfg, exp_last_source))
            return False
    def get_actual_boot_dev_info(self):
        '''
        Get actual boot order details
        Procedure to actual boot order details
        Return:
            Object populated with host eth interface details : SUCCESS
            False : FAILURE
        Author : jchanda
        '''
        try:
            boot_order_list_new = []
            output = self.mgmt_handle.execute_cmd_list('top', 'scope bios', 'show actual-boot-order detail', wait_time=60)
            attr_list = ['Order', 'DeviceName', 'DeviceType', 'RN', 'Slot', 'Port', 'Lun', 'SubType']
            actual_boot_order = []
            out_list = output.split("---")
            for block in out_list[1:]:
                boot_order_list = []
                for attr in attr_list:
                    value = re.search(attr + r':\s+([^\r\n.$]+)', block)
                    if value != None:
                        value = value.group(1)
                        boot_order_list.append(value)
                out = re.search(r'DeviceType:\s+([^\r\n]+)', block)
                if out != None:
                    device_type = out.group(1)
                    log.info('Adding boot object details for device ' + device_type)
                    boot_order_list_new.append(device_type)
                    if device_type == 'HDD':
                        log.info('%s boot device details are %s' %(device_type, str(boot_order_list)))
                        actual_boot_order.append(ActBootOrderDetails(boot_order_list[0], boot_order_list[1],
                                                                     boot_order_list[2], boot_order_list[3],
                                                                     None, None, None))
                    elif device_type == 'SAN' or device_type == 'PXE':
                        log.info('%s boot device details are %s' %(device_type, str(boot_order_list)))
                        actual_boot_order.append(ActBootOrderDetails(boot_order_list[0], boot_order_list[1],
                                                                     boot_order_list[2], boot_order_list[3],
                                                                     None))
                    elif device_type == 'VMEDIA':
                        log.info('%s boot device details are %s' %(device_type, str(boot_order_list)))
                        actual_boot_order.append(ActBootOrderDetails(boot_order_list[0], boot_order_list[1],
                                                                     boot_order_list[2], boot_order_list[3],
                                                                     None, None, boot_order_list[4]))
                    #### JRC, added for defect work-around, need to remove
                    ####Remove this USB
                    elif device_type == 'USB':
                        log.info('%s boot device details are %s' %(device_type, str(boot_order_list)))
                        actual_boot_order.append(ActBootOrderDetails(boot_order_list[0], boot_order_list[1],
                                                                     boot_order_list[2], boot_order_list[3],
                                                                     None, None))                
                    elif device_type == 'SDCARD' or device_type == 'EFI':
                        log.info('%s boot device details are %s' %(device_type, str(boot_order_list)))
                        actual_boot_order.append(ActBootOrderDetails(boot_order_list[0], boot_order_list[1],
                                                                     boot_order_list[2], boot_order_list[3]))
                    else:
                        log.info('Not matching device type for %s' %(device_type))
            self.actual_boot_order = actual_boot_order
            self.device_type_arr.insert(0, 'data')
            for boot_dev in self.actual_boot_order:
                self.actual_boot_order_dict[boot_dev.order] = boot_dev.device_type + boot_dev.order
                self.device_type_arr.insert(int(boot_dev.order), boot_dev.device_type)
    
            log.info('After adding device to array' + str(self.device_type_arr))
            self.boot_order_list_new = boot_order_list_new
            return actual_boot_order
        except:
            dump_error_in_lib()
            return False
    def l2_create_boot_device_all(self):
        '''Procedure to create L2 boot order device'''
        log.info('Creating all possible boot device for the testbed')
        self.created_boot_device = []
        device_name = None
        for i in range(1, len(self.device_type_arr)):
            log.info(self.device_type_arr[i])
            if re.search('HDD', self.device_type_arr[i]):
                device_name = 'myHDD' + str(i)
                device_type = 'LOCALHDD'
            elif re.search('PXE', self.device_type_arr[i]):
                device_name = 'myPXE' + str(i)
                device_type = 'PXE'
            elif re.search('EFI', self.device_type_arr[i]):
                device_name = 'myEFI' + str(i)
                device_type = 'UEFISHELL'
            elif re.search('VMEDIA', self.device_type_arr[i]):
                device_name = 'myVMEDIA' + str(i)
                device_type = 'VMEDIA'
            elif re.search('USB', self.device_type_arr[i]):
                device_name = 'myUSB' + str(i)
                device_type = 'USB'
            elif re.search('ISCSI', self.device_type_arr[i]):
                device_name = 'myISCSI' + str(i)
                device_type = 'ISCSI'
            elif re.search('SAN', self.device_type_arr[i]):
                device_name = 'mySAN' + str(i)
                device_type = 'SAN'
            elif re.search('PCHSTORAGE', self.device_type_arr[i]):
                device_name = 'myPCH' + str(i)
                device_type = 'PCHSTORAGE'
            elif re.search('SDCARD', self.device_type_arr[i]):
                device_name = 'mySDCARD' + str(i)
                device_type = 'SDCARD'
            elif re.search('NVME', self.device_type_arr[i]):
                device_name = 'myNVME' + str(i)
                device_type = 'NVME'
            else:
                log.warning('Not matching any device under device array list' + str(self.device_type_arr[i]))
            if device_name != None:
                out = self.mgmt_handle.execute_cmd('create-boot-device ' + device_name + ' ' + device_type,
                                                   wait_time=5)
                if out not in 'Invalid device type':
                    self.created_boot_device.append(device_name)
    def l2_get_boot_device_name(self):
        '''Procedure get created L2 booted device name'''
        log.info('Get all created boot device name')
        device_name_list = []
        out = self.mgmt_handle.execute_cmd_list('top', 'scope bios', 'show boot-device detail', wait_time=60)
        log.info('boot order details out :' + str(out))
        for block in out.split('---')[1:]:
            value = re.search(r'name:\s+([^\r\n]+)', block)
            if value != None:
                value = value.group(1)
                device_name_list.append(value)
        self.device_name_list = device_name_list
        log.info('List of available boot device are:' + str(self.device_name_list))
        return device_name_list
    def remove_boot_dev(self, device_name=None):
        '''Procedure to remove boot device'''
        self.mgmt_handle.execute_cmd_list('top', 'scope bios')
        if device_name is None:
            self.l2_get_boot_device_name()
            for device_name in self.device_name_list:
                self.mgmt_handle.execute_cmd('remove-boot-device ' + device_name, wait_time=5)
        else:
            self.mgmt_handle.execute_cmd('remove-boot-device ' + device_name, wait_time=5)
    def enable_boot_device(self, device_name=None):
        '''Procedure to enable the boot device'''
        self.mgmt_handle.execute_cmd('top', 'scope bios')
        if device_name is None:
            self.mgmt_handle.execute_cmd_list('scope boot-device ' + device_name)
            self.mgmt_handle.execute_cmd('set state Enabled')
            self.mgmt_handle.execute_cmd('set order 1')
            out = self.mgmt_handle.execute_cmd('commit', wait_time=5)
            try:
                if out in 'Continue':
                    self.mgmt_handle.execute_cmd('y')
            except:
                dump_error_in_lib()
                return False
        else:
            self.mgmt_handle.execute_cmd('scope boot-device ' + device_name)
            self.mgmt_handle.execute_cmd('set state Enabled')
            self.mgmt_handle.execute_cmd('set order 1')
            self.mgmt_handle.execute_cmd('commit', wait_time=6)
    def create_and_config_localhdd_boot_device(self, device_type, dev_order='1'):
        '''Procedure to create and configure LOCALHDD boot device'''
        log.info('Create and configuring %s boot device' %(device_type))
        slot = self.storage_util_obj.get_storage_adapter_slot()
        if slot is False:
            return False
        device_type_map_dic = {'HDD': 'LOCALHDD'}
        self.mgmt_handle.execute_cmd_list('top', 'scope bios')
        for boot_dev in self.actual_boot_order:
            if boot_dev.device_type == device_type:
                device_name = 'myHDD'
                device_type_map = device_type_map_dic[device_type]
                device_slot = slot
                order = dev_order
                found_boot_device = '1'
                break
        try:
            found_boot_device
        except NameError:
            log.error('LOCALHDD boot device not found on testbed')
            return 'SKIP'
        ''' create boot device '''
        out = self.mgmt_handle.execute_cmd('create-boot-device ' + device_name + ' ' + \
                                           device_type_map, wait_time=5)
        if 'Invalid device type' in out:
            log.error('Failed to create boot device, got error as: ' + out)
            return False
        else:
            log.info('Successfully created boot device %s'%(device_name))
        # Assign the values to class for verify after host reboot
        self.boot_order_obj = ActBootOrderDetails('1', 'PCI RAID Adapter', device_type, device_name, device_slot)
        if self.boot_mode == 'Legacy':
            self.boot_order_obj = ActBootOrderDetails('1', 'PCI RAID Adapter', device_type, device_name, device_slot)
        elif self.boot_mode == 'Uefi':
            self.boot_order_obj = ActBootOrderDetails('1', '<EFI> Boot Manager', 'EFI', device_name, device_slot)
        self.mgmt_handle.execute_cmd_list('scope boot-device ' + device_name, 'set state Enabled',
                                          'set order ' + order, 'set slot ' + device_slot)
        out = self.mgmt_handle.execute_cmd('commit', wait_time=6)
        try:
            if 'Enabling boot device will overwrite Legacy Boot Order configuration' in out:
                out = self.mgmt_handle.execute_cmd('y')
                if 'Commiting device configuration' in out:
                    return True
                else:
                    return False
        except:
            log.warning('Ignoring error')
            return True
    def powercycle_and_wait_for_host_comes_up(self):
        '''Wrapper procedure to power cycle the host'''
        log.info('Power cycling host')
        self.cimc_utils_obj.power_cycle_host()
        host_ip = common_utils.get_host_mgmt_ip(self.config)
        res = self.cimc_utils_obj.verify_host_up(host_ip, wait_for_ping_fail=False)
        if res is False:
            log.warning('Failed to ping the host')
            return False
        else:
            log.info("Host IP pinging successfully")
            return True
    def reboot_cimc(self, config):
        '''Wrapper procedure to reboot CIMC'''
        log.info('Reboot BMC')
        res = self.cimc_utils_obj.reboot_bmc_and_connect(config)
        if res is not True:
            return False
        else:
            return True
    def apc_cycle(self, config):
        '''Wrapper procedure for APC cycle'''
        log.info('Performing AC cycle')
        res = self.cimc_utils_obj.ac_cycle_and_reconnect(config)
        if res is not True:
            return False
        else:
            return True
    def reboot_operations(self, comp):
        '''Procedure call different reboot operation'''
        log.info('Performing reboot of %s' %(comp))
        if comp == 'host':
            res = self.powercycle_and_wait_for_host_comes_up()
        elif comp == 'cimc':
            res = self.reboot_cimc(self.config)
        elif comp == 'apc_cycle':
            res = self.apc_cycle(self.config)
        else:
            log.error('Unknown reboot component')
            return False
        if res is True:
            log.info('Reboot operation successful for %s' %(comp))
            return True
        else:
            log.info('Reboot operation failed for %s' %(comp))
            return False
    def verify_host_booted_from_configured_device(self, device_type):
        '''Procedure to verify host booted from configured boot device'''
        log.info('Validating actual boot order details for %s' %(device_type))

        if self.get_actual_boot_dev_info() is False:
            log.error('Failed to get actual boot order info')
            return False
        log.info('Validating %s device type in actual boot order list' %(device_type))
        log.info('order: ' + self.boot_order_obj.order)
        log.info('device name: ' + self.boot_order_obj.device_name)
        log.info('device type: ' + self.boot_order_obj.device_type)
        log.info('RN: ' + self.boot_order_obj.rn)
        for boot_dev in self.actual_boot_order:
            if boot_dev.order == '1':
                if device_type == 'HDD':
                    if boot_dev.rn == self.boot_order_obj.rn:
                        log.info('Verified, Host is booted into LOCALHDD boot device ' + self.boot_order_obj.rn)
                        break
                elif device_type == 'PXE':
                    if boot_dev.rn == self.boot_order_obj.rn:
                        log.info('Verified, Host is booted into PXE boot device ' + self.boot_order_obj.device_name)
                        break
                elif device_type == 'SAN':
                    if boot_dev.rn == self.boot_order_obj.rn:
                        log.info('Verified, Host is booted into SAN boot device ' + self.boot_order_obj.device_name)
                        break
                elif device_type == 'SDCARD':
                    if boot_dev.rn == self.boot_order_obj.rn:
                        log.info('Verified, Host is booted into SDCARD boot device ' + self.boot_order_obj.device_name)
                        break
                elif device_type == 'USB':
                    if boot_dev.rn == self.boot_order_obj.rn:
                        log.info('Verified, Host is booted into USB boot device ' + self.boot_order_obj.device_name)
                        break
                elif device_type == 'VMEDIA':
                    if boot_dev.rn == self.boot_order_obj.rn:
                        log.info('Verified, Host is booted into VMEDIA boot device ' + self.boot_order_obj.device_name)
                        break
                elif device_type == 'EFI':
                    if boot_dev.rn == self.boot_order_obj.rn:
                        log.info('Verified, Host is booted into boot UEFISHELL device ' + self.boot_order_obj.device_name)
                        break                   
                elif device_type == 'ISCSI':
                    if boot_dev.rn == self.boot_order_obj.rn:
                        log.info('Verified, Host is booted into boot ISCSI device ' + self.boot_order_obj.device_name)
                        break
                if device_type == 'FDD':
                    if boot_dev.rn == self.boot_order_obj.rn:
                        log.info('Verified, Host is booted into basic boot device ' + self.boot_order_obj.rn)
                        break                    
            else:
                log.error('Failed to verify host is booted into %s boot device' %(device_type))
                return False
        return True
    def create_and_config_pxe_boot_device(self, slot_id, port_id, device_type, wrong_slot='None'):
        '''Procedure to create and configure the PXE boot device'''
        log.info('Creating and configuring boot device for %s' %(device_type))
        # boot_mode = self.get_boot_mode()
        if self.boot_mode == 'Legacy':
            boot_device_type = 'PXE'
        elif self.boot_mode == 'Uefi':
            boot_device_type = 'EFI'
        else:
            log.error('Unable to get configured boot mode')
            return False
        self.mgmt_handle.execute_cmd_list('top', 'scope bios')
        #for boot_dev in self.actual_boot_order:
        #    if boot_dev.device_type == boot_device_type:
        log.info('PXE boot device found on testbed')
        device_name = 'myPXE'
        device_type = device_type
        device_port = port_id
        if wrong_slot != 'None':
            device_slot = wrong_slot
        else:
            device_slot = slot_id
        found_boot_device = '1'
        #break
        try:
            found_boot_device
        except NameError:
            log.error('PXE boot device not found on testbed')
            return 'SKIP'
        ''' create boot device '''
        out = self.mgmt_handle.execute_cmd('create-boot-device ' + device_name + ' ' +
                                           device_type, wait_time=5)
        if 'Invalid device type' in out:
            log.error('Failed to create boot device, got error as: ' + out)
            return False
        else:
            log.info('Successfully created boot device %s' %(device_name))
        # Assigning the values to constructor for later verification
        if self.boot_mode == 'Legacy':
            self.boot_order_obj = ActBootOrderDetails('1', device_name, device_type, device_name, slot_id)
        elif self.boot_mode == 'Uefi':
            self.boot_order_obj = ActBootOrderDetails('1', device_name, 'EFI', device_name, device_slot)
                    
        self.mgmt_handle.execute_cmd_list('scope boot-device ' + device_name, 'set state Enabled',
                                          'set order 1', 'set slot ' + device_slot, 'set port ' + device_port)
        out = self.mgmt_handle.execute_cmd('commit', wait_time=6)
        try:
            if 'Enabling boot device will overwrite Legacy Boot Order configuration' in out:
                out = self.mgmt_handle.execute_cmd('y')
                if 'Commiting device configuration' in out:
                    return True
                else:
                    return False
        except:
            log.warning('Ignoring error')
            return True
    def create_and_config_usb_boot_device(self, usb_sub_type):
        '''Procedure to create and configure the USB boot device'''
        log.info('Creating and configuring USB bootdevice')
        self.mgmt_handle.execute_cmd_list('top', 'scope bios')

        usb_device_sub_type_map = {'HDD': 'usb-hdd', 'CD': 'usb-cd', 'FDD': 'usb-fdd'}
        for boot_dev in self.actual_boot_order:
            if boot_dev.device_type == 'USB':
                if boot_dev.sub_type == usb_device_sub_type_map[usb_sub_type]:
                    log.info('USB boot device with sub type %s found on testbed' %(usb_sub_type))
                    device_name = 'myUSB_' + usb_sub_type
                    device_type = 'USB'
                    device_sub_type = usb_sub_type
                    found_boot_device = '1'
                    break
        try:
            found_boot_device
        except NameError:
            log.error('USB boot device with sub type %s not found on testbed' 
                      %(usb_device_sub_type_map[usb_sub_type]))
            return 'SKIP'
        ''' create boot device '''
        out = self.mgmt_handle.execute_cmd('create-boot-device ' + device_name + ' ' + 
                                           device_type, wait_time=5)
        if 'Invalid device type' in out:
            log.error('Failed to create boot device, got error as: ' + out)
            return False
        else:
            log.info('Successfully created boot device %s' %(device_name))
        # Assign the values to class for verify after host reboot        
        self.boot_order_obj = ActBootOrderDetails('1', device_name, device_type, device_name, 'None', 'None', usb_device_sub_type_map[usb_sub_type])
        self.mgmt_handle.execute_cmd_list('scope boot-device ' + device_name, 'set state Enabled',
                                          'set order 1', 'set subtype ' + device_sub_type)
        out = self.mgmt_handle.execute_cmd('commit', wait_time=6)
        print(out)
        try:
            if 'Enabling boot device will overwrite Legacy Boot Order configuration' in out:
                out = self.mgmt_handle.execute_cmd('y')
                if 'Commiting device configuration' in out:
                    return True
                else:
                    return False
        except:
            log.warning('Ignoring error')
            return True
    def create_and_config_san_boot_device(self, device_type, device_slot):
        '''Procedure to create and configure the SAN boot device'''
        log.info('Creating and configuring boot device for %s' %(device_type))
        if self.boot_mode == 'Legacy':
            boot_device_type = 'SAN'
        elif self.boot_mode == 'Uefi':
            boot_device_type = 'EFI'
        self.mgmt_handle.execute_cmd_list('top', 'scope bios')
        for boot_dev in self.actual_boot_order:
            log.info('boot device: ' + boot_dev.order)
            log.info('boot device type: ' + boot_dev.device_type)
            if boot_dev.device_type == boot_device_type:
                device_name = 'mySAN'
                device_type = device_type
                device_slot = device_slot
                found_boot_device = '1'
                break
        try:
            found_boot_device
        except NameError:
            log.error('SAN boot device not found on testbed')
            return 'SKIP'
        ''' create boot device '''
        out = self.mgmt_handle.execute_cmd('create-boot-device ' + device_name + ' ' + 
                                           device_type, wait_time=5)
        if 'Invalid device type' in out:
            log.error('Failed to create boot device, got error as: ' + out)
            return False
        else:
            log.info('Successfully created boot device %s' %(device_name))
        # Assign the values to class to verify after host reboot
        if self.boot_mode == 'Legacy':
            log.info('creating legacy object')
            self.boot_order_obj = ActBootOrderDetails('1', device_name, device_type, device_name, device_slot)
        elif self.boot_mode == 'Uefi':
            log.info('creating legacy UEFI object')
            self.boot_order_obj = ActBootOrderDetails('1', device_name, 'EFI', device_name, device_slot)
        self.mgmt_handle.execute_cmd_list('scope boot-device ' + device_name, 'set state Enabled',
                                          'set order 1', 'set slot ' + device_slot)
        out = self.mgmt_handle.execute_cmd('commit', wait_time=6)
        try:
            if 'Enabling boot device will overwrite Legacy Boot Order configuration' in out:
                out = self.mgmt_handle.execute_cmd('y')
                if 'Commiting device configuration' in out:
                    return True
                else:
                    return False
        except:
            log.warning('Ignoring error')
            return True
    def create_and_config_sdcard_boot_device(self, device_type, partition):
        '''Procedure to create and configure the SDCARD boot device'''
        log.info('Creating and configuring %s boot device for %s' %(device_type, partition))
        sdcard_partition_id = {'UserPartition': '4', 'SCU': '1', 'HUU': '2', 'Drivers': '3', 'Hypervisor': '1'}
        self.mgmt_handle.execute_cmd_list('top', 'scope bios')
        for boot_dev in self.actual_boot_order:
            if boot_dev.device_type == 'SDCARD':
                device_name = 'mySDCARD'
                device_type = device_type
                device_lun = sdcard_partition_id[partition]
                found_boot_device = '1'
                break
        try:
            found_boot_device
        except NameError:
            log.error('SDCARD boot device not found on testbed')
            return 'SKIP'
        ''' create boot device '''
        out = self.mgmt_handle.execute_cmd('create-boot-device ' + device_name + ' ' + 
                                           device_type, wait_time=5)
        if 'Invalid device type' in out:
            log.error('Failed to create boot device, got error as: ' + out)
            return False
        else:
            log.info('Successfully created boot device %s' %(device_name))
        out = self.mgmt_handle.execute_cmd('commit', wait_time=6)
        # Assign the values to class for verify after host reboot
        if self.boot_mode == 'Legacy':
            self.boot_order_obj = ActBootOrderDetails('1', 'CiscoVD UserPartition', device_type, device_name)
        elif self.boot_mode == 'Uefi':
            self.boot_order_obj = ActBootOrderDetails('1', 'CiscoVD Hypervisor', 'EFI', device_name)
        
        self.mgmt_handle.execute_cmd_list('scope boot-device ' + device_name, 'set state Enabled',
                                          'set order 1', 'set lun ' + device_lun)        
        out = self.mgmt_handle.execute_cmd('commit', wait_time=6)
        try:
            if 'Enabling boot device will overwrite Legacy Boot Order configuration' in out:
                out = self.mgmt_handle.execute_cmd('y')
                if 'Commiting device configuration' in out:
                    return True
                else:
                    return False
        except:
            log.warning('Ignoring error')
            return True
    def create_and_config_vmedia_boot_device(self, vmedia_sub_type):
        '''Procedure to create and configure the VMEDIA boot device'''
        log.info('Creating and configuring VMEDIA boot device of subtype %s' %(vmedia_sub_type))
        self.mgmt_handle.execute_cmd_list('top', 'scope bios')

        vmedia_device_sub_type_map = {'cimc-mapped-dvd': 'CIMCDVD', 'cimc-mapped-hdd': 'CIMCHDD',
                                      'kvm-mapped-dvd': 'KVMDVD'}      
        for boot_dev in self.actual_boot_order:
            if boot_dev.device_type == 'VMEDIA':
                if boot_dev.sub_type == vmedia_sub_type:
                    device_name = 'myVMEDIA_' + vmedia_sub_type
                    device_type = 'VMEDIA'
                    device_sub_type = vmedia_device_sub_type_map[vmedia_sub_type]
                    found_boot_device = '1'
                    break
        try:
            found_boot_device
        except NameError:
            log.error('VMEDIA boot device with sub type %s not found on testbed' %(vmedia_sub_type))
            return 'SKIP'
        ''' create boot device '''
        out = self.mgmt_handle.execute_cmd('create-boot-device ' + device_name + ' ' + 
                                           device_type, wait_time=5)
        if 'Invalid device type' in out:
            log.error('Failed to create boot device, got error as: ' + out)
            return False
        else:
            log.info('Successfully created boot device %s' %(device_name))

        self.boot_order_obj = ActBootOrderDetails('1', device_name, device_type, device_name, 'None', 'None', vmedia_sub_type)

        if self.boot_mode == 'Legacy':
            self.boot_order_obj = ActBootOrderDetails('1', device_name, device_type, device_name, 'None', 'None', vmedia_sub_type)            
        elif self.boot_mode == 'Uefi':
            self.boot_order_obj = ActBootOrderDetails('1', device_name, 'EFI', device_name, 'None', 'None', vmedia_sub_type)
            
        self.mgmt_handle.execute_cmd_list('scope boot-device ' + device_name, 'set state Enabled',
                                          'set order 1', 'set subtype ' + device_sub_type)
        out = self.mgmt_handle.execute_cmd('commit', wait_time=6)
        try:
            if 'Enabling boot device will overwrite Legacy Boot Order configuration' in out:
                out = self.mgmt_handle.execute_cmd('y')
                if 'Commiting device configuration' in out:
                    return True
                else:
                    return False
        except:
            log.warning('Ignoring error')
            return True
    def check_vmedia_mapping(self, device_type=None, config=None):
        '''Procedure to check vmedia mapping exists, if not it will create mappings'''
        log.info('Check if vmedia mapping already exists for %s, if not create map' %(device_type))
        if device_type == 'cimc-mapped-dvd':
            drive_type = 'CD'
        elif device_type == 'cimc-mapped-hdd':
            drive_type = 'Removable Disk'
        out = self.mgmt_handle.execute_cmd_list('top', 'scope vmedia', 'show mappings detail')
        map_found = False
        regex = r'driveType:\s+' + drive_type
        for block in out.split('---')[1:]:
            if re.search(regex, block) and re.search(r'mappingStatus:\s+OK', block):
                map_found = True
                return True
        if map_found is False:
            if self.create_vmedia_mapping(drive_type=drive_type) is True:
                self.powercycle_and_wait_for_host_comes_up()
                return True
            else:
                return False
    def create_vmedia_mapping(self, drive_type):
        '''Procedure to create VMEDIA mapping'''
        log.info('create vmedia mapping')
        platform_type = self.config.mgmtdetail.platform_series
        if drive_type == 'CD':
            if platform_type == 'M5':
                remote_file_to_map = 'RHEL-7.3-20161019.0-Server-x86_64-dvd1.iso'
            else:
                remote_file_to_map = 'scu_debug.iso'
        elif drive_type == 'Removable Disk':
            remote_file_to_map = 'new_dd_sol_scu_2_2_1.img'
        else:
            log.error('Unknown drive type')
            return False
        command = 'map-nfs '
        command += 'test_' + drive_type.split()[0]
        command += ' '
        command += '10.127.54.176:/nfsdata '
        command += remote_file_to_map
        print('Final command :' + str(command))
        self.mgmt_handle.execute_cmd_list('top', 'scope vmedia', command, wait_time=5)
        time.sleep(2)
        out = self.mgmt_handle.execute_cmd_list('top', 'scope vmedia', 'show mappings detail')
        for block in out.split('---')[1:]:
            if re.search(r'driveType:\s' + drive_type, block) and re.search(r'mappingStatus:\s+OK', block):
                log.info('Successfully created vmedia mapping for drive type: ' + drive_type)
                return True
        log.error('Failed to create vmedia mapping for drive type: ' + drive_type)
        return False
    def l2_reverse_boot_device_name(self):
        '''Procedure create reverse boot order'''
        log.info('Reversing created boot device name')
        normal_list = self.device_name_list
        length_of_boot_device = len(normal_list)
        reversed_list = list(reversed(range(1, length_of_boot_device + 1)))
        for (boot_device, priority) in zip(normal_list, reversed_list):
            self.mgmt_handle.execute_cmd_list('top', 'scope bios')
            self.mgmt_handle.execute_cmd('rearrange-boot-device ' + str(boot_device) + ":" + str(priority))
            self.mgmt_handle.execute_cmd('commit', wait_time=6)
    def l2_boot_comparison_between_cimc_boot_actual(self):
        '''Procedure to compare L2 boot device and actual boot device'''
        log.info("Boot Order comparison between Actual boot device and  CIMC boot device")
        out = self.mgmt_handle.execute_cmd_list('top', 'scope bios', 'show actual-boot-order detail', wait_time=30)
        actual_boot_type = list1 = []
        for block in out.split('---')[1:]:
            value = re.search(r'DeviceType:\s+([^\r\n.$]+)', block)
            if value != None:
                value = value.group(1)
            actual_boot_type.append(value)
        list2 = self.l2_get_boot_device_name()[1]
        match = 0
        list3 = [words.replace('EFI', 'UEFISHELL') for words in list1]
        log.info("list2" + str(list2))
        log.info("list3" + str(list3))
        if len(list2) == len(list3):
            for i in range(len(list3)):
                if list2[i] == list3[i]:
                    match = 1
                else:
                    log.error("Unmatch found")
                    log.info(list2[i])
        else:
            log.info("Length  not matched")
        if match == 1:
            log.info("all device types are matched")
    def create_and_config_uefishell_boot_device(self, device_type):
        '''
        device_type --> Type of Boot device
        device_type1 --> Recommnded for UEFI boot type and of other boot device can assign as device_type1 = device_type
        device_name --> L2 Boot customize_name
        '''
        log.info('Create and configuring ' + str(device_type) + ' boot device')
        self.mgmt_handle.execute_cmd_list('top', 'scope bios')
        for boot_dev in self.actual_boot_order:
            if boot_dev.device_type == device_type:
                device_name = 'myUEFI_' + device_type
                device_type_actual = 'UEFISHELL'
                found_boot_device = '1'
                break
            else:
                log.info('device type %s not matching' %(device_type))
                log.info(boot_dev.device_type)
        try:
            found_boot_device
        except NameError:
            log.error(' boot device not found on testbed  ' + device_type)
            return 'SKIP'
        ''' create boot device '''
        out = self.mgmt_handle.execute_cmd('create-boot-device ' + device_name + ' ' + 
                                           device_type_actual, wait_time=5)
        if 'Invalid device type' in out:
            log.error('Failed to create boot device, got error as: ' + out)
            return False
        else:
            log.info('Successfully created boot device %s' %(device_name))

        self.boot_order_obj = ActBootOrderDetails('1', 'Built-in EFI Shell', 'EFI', device_name)
        self.mgmt_handle.execute_cmd_list('scope boot-device ' + device_name, 'set state Enabled',
                                          'set order 1')
        out = self.mgmt_handle.execute_cmd('commit', wait_time=6)
        print(out)
        try:
            if 'Enabling boot device will overwrite Legacy Boot Order configuration' in out:
                out = self.mgmt_handle.execute_cmd('y')
                if 'Commiting device configuration' in out:
                    log.info(self.mgmt_handle.execute_cmd_list('show detail'))
                    return True
                else:
                    return False
        except:
            log.warning('Ignoring error')
            log.info(self.mgmt_handle.execute_cmd_list('show detail'))
            return True
        
    def boot_to_efi_shell(self, post_flag=False):
        '''
        This proc will set the boot order to EFI
        And will boot the system to efi shell
        Return True if the EFI shell prompt is obtained.
        '''

        # Create a serial session using  object
        try:
            boot_device = self.check_first_boot_device()
            if 'EFI' not in boot_device:
                log.info(
                    "EFI is not the first boot, Changing boot order to EFI")
                boot_out = self.change_boot_order('efi', post_flag=post_flag)
                if boot_out is False:
                    log.error("Unable to change boot order to efi")
                    return False
                out1 = self.telnet_handle.connect_to_host_efi(
                    post_flag=post_flag)
                if out1 is None:
                    log.error("Failed to connect efi")
                    return False
                else:
                    log.info("Successfully Connected \
                                to EFI shell: Ready to execute EFI commands")
                    return out1
            else:
                log.info("Already in EF1 Mode")
                out1 = self.telnet_handle.connect_to_host_efi(
                    post_flag=post_flag)
                if out1 is None:
                    log.error("Failed to connect efi")
                    return False
                else:
                    log.info("Successfully Connected \
                                to EFI shell: Ready to execute EFI commands")
                    return out1
        except:
            dump_error_in_lib()
            return False

    def change_boot_order(self, boot_option='hdd',  post_flag=False):
        '''
        Procedure to change boot order
        Parameter:
             Boot option: Default - hdd
             or
             Pass the appropriate device name to change the boot order
        Return:
            True : Success
            False : Failure
        Author: Suren kumar Moorthy
        '''
        try:
            log.info(self.mgmt_handle.execute_cmd('top'))
            log.info(self.mgmt_handle.execute_cmd('scope bios'))
            log.info(
                self.mgmt_handle.execute_cmd('set boot-order ' + boot_option))
            ### JRC commented
            #log.info(self.mgmt_handle.execute_cmd('y'))
            # Commit the changes
            #log.info(self.mgmt_handle.execute_cmd('top'))
            # output=self.handle.execute_cmd('commit')
            commit_out = self.mgmt_handle.execute_cmd('commit', wait_time=120)
            log.info("commit output :" + commit_out)
            if re.search('ERROR', commit_out, re.IGNORECASE):
                log.info('Unable to set parameter ')
                self.mgmt_handle.execute_cmd('discard')
                return False
            elif re.search('Do you want to reboot the system', commit_out):
                reboot_out = self.mgmt_handle.execute_cmd('y', wait_time=60)
                if 'A system reboot has been initiated' in reboot_out:
                    log.info('Successfully set and host reboot initiated.')
                    if not post_flag:
                        time.sleep(180)
                else:
                    log.error(
                        'Failed to initiate host reboot after setting bios token')
                    return False
            else:
                reboot_out = self.cimc_utils_obj.power_cycle_host(
                    wait_time=180)
                if not post_flag:
                    time.sleep(180)
                return reboot_out
        except:
            dump_error_in_lib()
            return False

    def check_first_boot_device(self):
        '''
        Procedure to check first boot device
        Parameter:
            Parameters: None
        Return:
            True : Success
            False : Failure
        Author: Suren kumar Moorthy
        '''        
        try:
            out = self.mgmt_handle.execute_cmd_list('top', 'scope bios', 'show actual-boot-order detail')
            log.info("Boot Order")
            log.info(out)
            regex = r'DeviceName\s*\:\s+([^\r\n]+)'
            return re.search(regex, out).group(1)
        except:
            dump_error_in_lib()
            return False   
    def create_and_configure_boot_device(self, device_type, con_obj):
        '''Procedure to create and configure boot device'''
        self.config_obj = self.config.boot_device_detail
        log.info('Create and configuring %s boot device' %(device_type))
        boot_config_values = self.config_obj[device_type]
        log.info(boot_config_values)
        log.info(self.config_obj[device_type])
        options = con_obj.options(device_type)
        for option in options:
            log.info(con_obj.get(device_type, option))
        boot_dev_dict = {}
        for option in options:
            boot_dev_dict[option] = con_obj.get(device_type, option)
        log.info('Boot device configure parameters and verify parameters dictionary')
        log.info(boot_dev_dict)
        boot_config_dict = {k:v for k, v in (x.split(':') for x in boot_dev_dict['config'].split(','))}
        log.info('Boot configure dictionary: ' + str(boot_config_dict))
        log.info('Verify whether actual boot device is available to create boot device')
        boot_mode = con_obj.get('BootDeviceDetail', 'boot_mode')
        if boot_mode == 'Legacy':
            for boot_dev in self.actual_boot_order:
                log.info('Actual boot order:' + boot_dev.device_type)
                log.info('Boot device name from config: ' + boot_dev_dict['device_type'])
                if boot_dev.device_type == boot_dev_dict['device_type']:
                    log.info('found boot device for device type %s' %(boot_dev_dict['device_type']))
                    found_boot_device = '1'
                    break
                elif re.search(boot_dev.device_type, boot_dev_dict['device_type']) is not None:
                    log.info('found boot device for device type %s' %(boot_dev_dict['device_type']))
                    found_boot_device = '1'
                    break
            try:
                found_boot_device
            except NameError:
                log.error('Boot device %s not found on testbed' %(boot_dev_dict['device_type']))
                return 'SKIP'
        ''' Create boot device'''
        log.info('Creating boot device')
        self.mgmt_handle.execute_cmd_list('top', 'scope bios')
        out = self.mgmt_handle.execute_cmd_list('create-boot-device ' + 
                                                device_type + ' ' + 
                                                boot_dev_dict['device_type'], wait_time=5)
        if 'Error:' in out or 'Invalid' in out:
            log.error('Failed to create boot device for device type, got error as: ' + out)
            return False
        else:
            log.info('Successfully created boot device for %s device type' %(device_type))
        if boot_dev_dict['device_type'] == 'LOCALHDD':
            boot_vd_pd_dict = {k:v for k, v in (x.split(':') for x in boot_dev_dict['boot_vd_pd'].split(','))}            
            if boot_vd_pd_dict['type'] == 'VD':
                res = self.storage_util_obj.configure_boot_vd(boot_vd_pd_dict['vd_pd_no'])
            elif boot_vd_pd_dict['type'] == 'PD':
                res = self.storage_util_obj.configure_boot_pd(boot_vd_pd_dict['vd_pd_no'])
            if res is False:
                log.error('Failed to set VD/PD as boot VD/PD')
                return False
            act_dev_type = 'HDD'
        else:
            act_dev_type = boot_dev_dict['device_type']
        try:
            self.boot_order_obj = ActBootOrderDetails(boot_config_dict['order'],
                                                      device_type,
                                                      act_dev_type,
                                                      device_type)          
        except:
            log.warning('Ignore the error')
        '''configure remaining parameters of boot device '''   
        self.mgmt_handle.execute_cmd_list('top',
                                          'scope bios',
                                          'scope boot-device ' + device_type,
                                          'set state Enabled')
        for key in boot_config_dict:
            self.mgmt_handle.execute_cmd('set ' + key + ' ' + boot_config_dict[key])        
        out = self.mgmt_handle.execute_cmd('commit', wait_time=6)
        try:
            if 'Enabling boot device will overwrite Legacy Boot Order configuration' in out:
                out = self.mgmt_handle.execute_cmd('y')
                if 'Commiting device configuration' in out:
                    return True
                else:
                    log.error('Expected message -Commiting device configuration- message not seen')
                    return False
        except:
            log.warning('Ignoring error')
            return True
    def create_basic_boot_order(self, boot_dev, act_boot_dev, reboot='yes', wait_for_host_reboot=None):
        '''
        Procedure to create basic boot order
        Parameter:
             boot_dev_type: One of dev type(hdd, pxe, fdd, efi, cdrom)
        Return:
            True : Success
            False : Failure
        Author: jchanda
        '''
        log.info('Create \'%s\' basic boot order' %(boot_dev))
        self.mgmt_handle.execute_cmd_list('top', 'scope bios')
        self.mgmt_handle.execute_cmd('set boot-order ' + boot_dev, wait_time=8)
        commit_out = self.mgmt_handle.execute_cmd('commit', wait_time=8)
        if 'Do you want to reboot the system' in commit_out:
            if reboot is 'yes':
                reboot_out = self.mgmt_handle.execute_cmd('y', wait_time=6)
                if 'A system reboot has been initiated' in reboot_out:
                    log.info('Created %s basic boot order' %(boot_dev))
                else:
                    log.error('Failed to initiate reboot after creating boot device')
                    return False
            else:
                reboot_out = self.mgmt_handle.execute_cmd('N', wait_time=6)
                if 'Changes will be applied on next reboot' in reboot_out:
                    log.info('Created boot device, need to reboot system')
                else:
                    log.error('Failed to create % boot device' %(boot_dev))
                    return False
        else:
            log.error('Failed to create basic boot device: ' + boot_dev)
            return False
        if wait_for_host_reboot is not None:
            '''A system reboot has been initiated.'''
            host_ip = common_utils.get_host_mgmt_ip(self.config)
            res = self.cimc_utils_obj.verify_host_up(host_ip, wait_for_ping_fail=False)
            if res is False:
                log.warning('Failed to ping the host, may be as expected')
            else:
                log.info('Host IP pinging successfully')
        try:
            self.boot_order_obj = ActBootOrderDetails('1',
                                                      boot_dev,
                                                      act_boot_dev,
                                                      boot_dev)      
        except:
            log.warning('Ignore the error')
        out = self.mgmt_handle.execute_cmd('show detail')
        if re.search('boot-order: '+boot_dev, out, re.I):
            log.info('Successfully created %s boot device' %(boot_dev))
            return True
        else:
            log.info('Failed to % boot device' %(boot_dev))
            return False
    
    def set_boot_order_HDD(self):
        try:
            platform_type = self.config.mgmtdetail.platform_series
            slot = ('MRAID' if platform_type == 'M5' else 'HBA')
            self.mgmt_handle.execute_cmd_list('top', 'scope bios', 'create-boot-device myHDD LOCALHDD')
            out = self.mgmt_handle.execute_cmd_list('scope boot-device myHDD', 'set state Enabled', 
                                              'set order 1', 'set slot '+slot)
            #out = self.mgmt_handle.execute_cmd_list(
            #    'top', 'scope bios', 'set boot-order HDD', wait_time=10)
            log.info(out)
            match = re.search(
                'invalid|exceeding|incomplete|Valid value|Maximum|cannot be used', out, re.I)
            time.sleep(2)
            if match is not None:
                log.error(
                    'Failed to execute command; got error as: ' + str(match))
                return False
            commit_out = self.mgmt_handle.execute_cmd('commit', wait_time=10)
            if 'Do you want to reboot the system' or 'Continue' in commit_out:
                log.info('inside Do u want to reboot check')
                reboot_out = self.mgmt_handle.execute_cmd('y', wait_time=10)
                if 'A system reboot has been initiated' or 'Commiting' in reboot_out:
                    log.info('Power cycling the host')
                    if self.powercycle_and_wait_for_host_comes_up() is False:                
                        return False
                    return True
                else:
                    log.error(
                        'Failed to initiate host reboot after setting bios token')
                    return False
            elif not commit_out:
                log.info('Power cycling the host')
                if self.powercycle_and_wait_for_host_comes_up() is False:           
                    return False
                return True
        except:
            dump_error_in_lib()
            return False