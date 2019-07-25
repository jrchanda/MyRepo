'''
vic_cdn_test.py
Purpose of test cases is to verify the CDN feature on VIC and LOM.

Author: jchanda
'''
import logging
from ats import aetest
from ats import easypy
from config_parser import ConfigParser
from common_test import Setup, Cleanup
from asyncio.log import logger
from vic_lib import VicLib
from linux_utils import LinuxUtils
from exp_imp_utils import ExpImpUtils
from firmware_utils import FirmwareUtils
from host_utils import HostUtils
from boot_order import BootOrder
import os

# Get your logger for your script
logger = logging.getLogger(__name__)

def get_host_mgmt_ip(config):
    ntw_list = config.host_info[0].nw_intf_list
    logger.info('Management interface is:' + ntw_list[0].is_mgmt_intf)
    for intf in ntw_list:
        if intf.is_mgmt_intf == 'yes':
            logger.info('Host Managment IP is: ' + intf.ip_address)
            host_ip = intf.ip_address
    return host_ip

def create_vnic_interface(self, vic_obj, slot_no, dev_list=[]):
    vnic_create = None
    #for dev in dev_list:
    for dev in dev_list:
        dev_name = 'eth_dev_'+dev+str(slot_no)
        cdnname = 'cdn_'+dev_name
        res = vic_obj.create_vnic(slot_no, dev_name, cdn_name=cdnname)
        if res is not True:
            logger.error('Failed to create vNIC interface for dev name: '+ dev_name)
            vnic_create = 'failed'
        else:
            logger.info('Successfully created vNIC with device name: ' + dev_name)
            self.created_vnic_list.append(slot_no+' '+dev_name)
    if vnic_create == 'failed':
        return False
    else:
        return True
class CommonSetup(Setup):
    '''
    Common Setup section which connects to CIMC
    '''
    @aetest.subsection
    def connect(self, testscript, testbed_name):
        super(CommonSetup, self).connect(testscript, testbed_name)
class CdnEnableTest(aetest.Testcase):
    @aetest.test
    def cdn_enable_test(self, cimc_util_obj, config):
        '''
        Logical ID: RACK-BIOS-DN-CDN-VIC-003
        Test Case: To Check CDN is Enabled from CIMC
        '''
        vic_list = config.inventory_detail
        logger.info('VIC list are: ' + str(vic_list))
        bios_obj = cimc_util_obj.bios_util_obj

        host_util = HostUtils()
        boot_order_obj = BootOrder(cimc_util_obj)
        status = host_util.check_host_up(cimc_util_obj, boot_order_obj, config)
        if status is False:
            logger.warning('Host OS is not pinging after setting the boot order to HDD ')

        bios_token = 'cdnEnable'
        token_new_value = 'Enabled'
        logger.info('Power on the host')
        if cimc_util_obj.set_host_power('on') is False:
            self.failed('Failed to power on host', goto=['cleanup'])
        host_ip = get_host_mgmt_ip(config)
        token_val = bios_obj.get_bios_token_value(bios_token)
        if token_val == token_new_value:
            logger.info('CDN is already enabled on CIMC')
        else:
            logger.info('Set the cdnEnable token Enable and Reboot the host')
            res = bios_obj.set_bios_token_value(bios_token, token_new_value)
            if res is False:
                logger.error('Failed to set bios token value')
                self.failed('Failed to set bios token value', goto=['cleanup'])
            '''Wait for host to reboot'''
            res = cimc_util_obj.verify_host_up(host_ip, wait_for_ping_fail=False, wait_time=400)
            if res is False:
                logger.warning('Failed to ping the host after host reboot')
                self.failed('Failed to ping host', goto=['cleanup'])
            scope = 'advanced'
            token_val = bios_obj.get_bios_token_value(bios_token)
            if token_val == token_new_value:
                self.passed('Successfully verified that CDN token can be enabled from CIMC')
            else:
                self.failed('Failed to verify that CDN token,\
                    Expected is:' + token_new_value + ' But got as: ' + token_val)
    @aetest.test
    def lom_cdn_test(self, cimc_util_obj, config):
        '''
        Logical ID: RACK-BIOS-DN-CDN-003
        Test Case: To Verify Consistent device naming structure for LOM Ports-RHEL 7.0
        Pass/Fail Criteria: Device Naming should appear as specified in the Functional Spec
        '''
        vic_obj = VicLib(cimc_util_obj, config)
        logger.info('Fetch the host managment interface IP')
        ntw_list = config.host_info[0].nw_intf_list
        logger.info('Management interface is:' + ntw_list[0].is_mgmt_intf)
        host_ip = get_host_mgmt_ip(config)
        res = cimc_util_obj.verify_host_up(host_ip, wait_time=400, wait_for_ping_fail=False)
        if res is False:
            logger.warning('Failed to ping the host after host reboot')
        else:
            logger.info("Host name IP pinging successfully")
        # connect to host
        cimc_util_obj.host_handle.connect()
        logger.info('Successfully connected to host')
        host_dict = vic_obj.host_cdn_mac_dict(cimc_util_obj.host_handle, 'biosdevname -d')
        cdn_name_from_host = []
        for cdn_name_from_host1 in host_dict.values():
            cdn_name_from_host.append(cdn_name_from_host1)
        if "LOMPort1" and "LOMPort2" in cdn_name_from_host:
            self.passed("LOMPort1 and LOMPort2 available in Host OS, when CDN Enabled")
        else:
            self.passed('LOMPort1 and LOMPort2 are not available in Host OS, when CDN Enabled')
    @aetest.cleanup
    def cleanup(self):
        logger.info('In cleanup section of CdnEnableTest')
class ConfigureModifyDeleteCDNTest(aetest.Testcase):
    @aetest.test
    def configure_modify_delete_cdn(self, cimc_util_obj, config):
        '''
        Logical ID: RACK-BIOS-DN-CDN-VIC-004
                    RACK-BIOS-DN-CDN-VIC-005
                    RACK-BIOS-DN-CDN-VIC-006
        Test Case: To Configure CDN for vNIC
                    To Modify CDN for vNIC
                    To Delete CDN for vNIC
        '''
        vic_list = []
        vic_obj = VicLib(cimc_util_obj, config)
        vic_list = config.inventory_detail
        self.created_vnic_list = []
        if cimc_util_obj.set_host_power('on') is False:
            self.failed('Failed to power on host', goto=['cleanup'])
        logger.info('VIC list: ' + str(vic_list))
        for vic in vic_list:
            logger.info('vic slot number is: ' + vic.slot_number)
            slot_no = vic.slot_number
            '''creating 2 vNIC interface'''
            self.created_vnic_list = []
            '''creating 2 vNIC interface'''
            dev_list = ['1', '2']
            if create_vnic_interface(self, vic_obj, slot_no, dev_list) is not True:
                self.failed('Failed to create vnic interface', goto=['cleanup'])
            res1 = vic_obj.powercycle_and_verify_cdn_on_cimc_and_host(slot_no)

            ''' modify one vnic and delete one vnic and verify'''
            val = self.created_vnic_list[0]
            slot_no = val.split(' ')[0]
            dev_name = val.split(' ')[1]
            res = vic_obj.modify_vnic_properties(slot_no, dev_name, 'CDN', 'modified_'+dev_name)
            if res is not True:
                logger.error('Failed to modify the CDN name attribute of vNIC')
            else:
                self.created_vnic_list.append(slot_no+' '+dev_name)
            '''Deleting the vNIC interface'''
            val = self.created_vnic_list[1]
            slot_no = val.split(' ')[0]
            dev_name = val.split(' ')[1]
            if vic_obj.delete_vnic(slot_no, dev_name) != True:
                logger.error('Failed to delete vNIC ethernet interface ' + dev_name)
            res2 = vic_obj.powercycle_and_verify_cdn_on_cimc_and_host(slot_no)
            if res1 == False & res2 == False:
                self.failed('Test cases failed')
            else:
                self.passed('Test Case Passed')
    @aetest.cleanup
    def cleanup(self, cimc_util_obj, config):
        logger.info('In clenup section of ConfigureModifyDeleteCDNTest')
        vic_obj = VicLib(cimc_util_obj, config)
        for val in self.created_vnic_list:
            slot_no = val.split(' ')[0]
            dev_name = val.split(' ')[1]
            logger.info('Delete vnic {} interface on slot {}'.format(dev_name, slot_no))
            vic_obj.delete_vnic(slot_no, dev_name)
class CDNDuplicateNameTest(aetest.Testcase):
    @aetest.test
    def cdn_duplicate_name_test(self, cimc_util_obj, config):
        '''
        Logical ID: RACK-BIOS-DN-CDN-VIC-014
        Test Case: Create Duplicate CDN Names
        Pass/Fail Criteria: Should not able to create Duplicate Names
        Author: lakkris2
        '''
        vic_list = []
        vic_obj = VicLib(cimc_util_obj, config)
        vic_list = config.inventory_detail
        self.created_vnic_list = []
        if cimc_util_obj.set_host_power('on') is False:
            self.failed('Failed to power on host', goto=['cleanup'])
        for vic in vic_list:
            logger.info('vic slot number is: ' + vic.slot_number)
            slot_no = vic.slot_number
            for dev_ in ['3']:
                dev_name = 'ethi_dev_'+ str(dev_)+ str(slot_no)
                cdnname = 'cdnk_'+dev_name
                res = vic_obj.create_vnic(slot_no, dev_name, cdn_name=cdnname)
                if res is not True:
                    logger.error('Failed to create vNIC interface')
                    self.failed('Failed to create vNIC', goto=['cleanup'])
                else:
                    self.created_vnic_list.append(slot_no+' '+dev_name)
                    logger.info('Successfully created vNIC with device name: ' + dev_name)
            ''' Creating vnic interface with Duplicate cdn name '''
            dev_name1 = 'dup_vnic_name'
            logger.info('Creating vnic interface {} with duplicate CDN {} name'\
                        .format(dev_name1, cdnname))
            out = vic_obj.create_vnic(slot_no, dev_name1, cdn_name=cdnname)
            if 'Duplicate CDN name exists, discarding it' in out:
                self.passed('Failed to created duplicate CDN name, as expected')
            else:
                self.failed('Able to create duplicate vNIC interface, Not expected',\
                             goto=['cleanup'])
    @aetest.cleanup
    def cleanup(self, cimc_util_obj, config):
        logger.info('In clenup section of CDNDuplicateNameTest')
        vic_obj = VicLib(cimc_util_obj, config)
        for val in self.created_vnic_list:
            slot_no = val.split(' ')[0]
            dev_name = val.split(' ')[1]
            logger.info('Delete vnic {} interface on slot {}'.format(dev_name, slot_no))
            vic_obj.delete_vnic(slot_no, dev_name)
class CDNExportTest(aetest.Testcase):
    @aetest.test
    def verify_export_vnic(self, cimc_util_obj, config, common_config):
        '''
        Logical ID: RACK-BIOS-DN-CDN-VIC-017
        Test Case: Export VIC Configuration and CDN Name
        Pass/Fail Criteria: CDN names and its details should appear in Exported file
        Author: lakkris2
        '''
        vic_obj = VicLib(cimc_util_obj, config)
        exp_obj = ExpImpUtils(cimc_util_obj, config, common_config)
        vic_list = config.inventory_detail
        self.created_vnic_list = []
        if cimc_util_obj.set_host_power('on') is False:
            self.failed('Failed to power on host', goto=['cleanup'])
        for vic in vic_list:
            logger.info('vic slot number is: ' + vic.slot_number)
            slot_no = vic.slot_number
            '''creating 2 vNIC interface'''
            dev_list = ['4', '5']
            if create_vnic_interface(self, vic_obj, slot_no, dev_list) is not True:
                self.failed('Failed to create vnic interface', goto=['cleanup'])
            out = exp_obj.export_vic_config(slot_no)
            if out is False:
                self.failed('Failed to export vic config', goto=['cleanup'])
            res = exp_obj.validate_vic_config(slot_no)
            if res is False:
                self.failed('Failed to verify that CDN info consistent across CIMC and VIC \
                exported files', goto=['cleanup'])
            else:
                self.passed('Successfully verified that CDN info consistent across \
                CIMC and VIC config')
            exp_obj.remove_vic_config()
    @aetest.cleanup
    def cleanup(self, cimc_util_obj, config):
        logger.info('In clenup section of CDNExportTest')
        vic_obj = VicLib(cimc_util_obj, config)
        for val in self.created_vnic_list:
            slot_no = val.split(' ')[0]
            dev_name = val.split(' ')[1]
            logger.info('Delete vnic {} interface on slot {}'.format(dev_name, slot_no))
            vic_obj.delete_vnic(slot_no, dev_name)
class BiosUpdateCdnTest(aetest.Testcase):
    @aetest.test
    def verify_cdn_update_bios(self, cimc_util_obj, config, common_config):
        '''
        Logical ID: RACK-BIOS-DN-CDN-VIC-012
        Test Case: Check CDN upgrade with BIOS update
        Pass/Fail Criteria: CDN Name should retain even after BIOS upgrade
        '''
        logger.info('To Verify CDN after BIOS Upgrade')
        self.created_vnic_list = []
        if cimc_util_obj.set_host_power('on') is False:
            self.failed('Failed to power on host', goto=['cleanup'])
        #sys_image = '/auto/savbu-rack-builds01/firmware-containers/delnorte1/freel_peak_mr2/3.0.2.26/images/CIMC/C220M4-3.0.2.26.zip'
        try:
            sys_image = os.environ['SYSTEM_IMAGE']
            logger.info('System image:' + sys_image)
        except KeyError:
            self.skipped('SYSTEM IMAGE not provided in the env, please set system image and run',\
                         goto=['cleanup'])
        vic_list = []
        vic_obj = VicLib(cimc_util_obj, config)
        vic_list = config.inventory_detail
        fw_utils_obj = FirmwareUtils(cimc_util_obj, common_config)
        for vic in vic_list:
            logger.info('vic slot number is: ' + vic.slot_number)
            slot_no = vic.slot_number
            '''creating vNIC interface'''
            dev_list = ['6']
            if create_vnic_interface(self, vic_obj, slot_no, dev_list) is not True:
                self.failed('Failed to create vnic interface', goto=['cleanup'])
            logger.info('Fetch CDN info before BIOS Update')
            cdn_before_update = vic_obj.cimc_cdn_mac_dict(slot_no)
            if cdn_before_update is False:
                self.failed('CIMC CDN mac list is empty', goto=['cleanup'])
            logger.info('Start updating BIOS firmware component')
            if fw_utils_obj.prepare_bios_image_file(sys_image) is not True:
                self.failed('Failed to prepare BIOS image CAP file', goto=['cleanup'])
            if fw_utils_obj.bios_update() is not True:
                self.failed('Failed to Update the BIOS component', goto=['cleanup'])
            logger.info('Fetch CDN info after BIOS Update')
            cdn_after_update = vic_obj.cimc_cdn_mac_dict(slot_no)
            if cdn_after_update is False:
                self.failed('CIMC CDN mac list is empty', goto=['cleanup'])
            match = True
            for key in cdn_before_update.keys():
                if key in cdn_after_update.keys():
                    if cdn_before_update[key] != cdn_after_update[key]:
                        logger.error('CDN name Before:' +cdn_before_update[key] + \
                                     'After Update: ' + cdn_after_update[key])
                        match = False
                    else:
                        logger.info('CDN name before update:' +cdn_before_update[key] + \
                                    'After Update:' + cdn_after_update[key])
            if match is True:
                logger.info('CDN Name retained before and after BIOS upgrade')
                self.passed('Test Passed')
            else:
                logger.info('CDN Name failed to retain after BIOS upgrade')
                self.failed('Test Failed')
    @aetest.cleanup
    def cleanup(self, cimc_util_obj, config):
        logger.info('In clenup section of BiosUpdateCdnTest')
        vic_obj = VicLib(cimc_util_obj, config)
        for val in self.created_vnic_list:
            slot_no = val.split(' ')[0]
            dev_name = val.split(' ')[1]
            logger.info('Delete vnic {} interface on slot {}'.format(dev_name, slot_no))
            vic_obj.delete_vnic(slot_no, dev_name)
class VicFirmwareUpdateCdnTest(aetest.Testcase):
    @aetest.test
    def verify_cdn_vic_fw_update(self, cimc_util_obj, config, common_config):
        '''
        Logical ID: RACK-BIOS-DN-CDN-VIC-020
        Test Case: Check CDN upgrade VIC Firmware
        Pass/Fail Criteria: CDN Name should retain even after Firmware upgrade
        '''
        logger.info('To Verify CDN after VIC Firmware Upgrade')
        #vic_fw_image = '/auto/savbu-rack-builds01/firmware-containers/delnorte1/freel_peak_mr2/3.0.2.26/images/Palo/fw/serenofw.bin'
        self.created_vnic_list = []
        if cimc_util_obj.set_host_power('on') is False:
            self.failed('Failed to power on host', goto=['cleanup'])
        try:
            vic_fw_image = os.environ['VIC_FW_IMAGE']
            logger.info('VIC FW Image:' + vic_fw_image)
        except KeyError:
            self.skipped('VIC FW IMAGE not provided in the env, please set system image and run',\
                         goto=['cleanup'])
        vic_list = []
        vic_obj = VicLib(cimc_util_obj, config)
        fw_utils_obj = FirmwareUtils(cimc_util_obj, common_config)
        vic_list = config.inventory_detail
        for vic in vic_list:
            logger.info('vic slot number is: ' + vic.slot_number)
            slot_no = vic.slot_number
            '''creating vNIC interface'''
            dev_list = ['7', '8']
            if create_vnic_interface(self, vic_obj, slot_no, dev_list) is not True:
                self.failed('Failed to create vnic interface', goto=['cleanup'])
            logger.info('Fetch CDN info before VIC Update')
            cdn_before_update = vic_obj.cimc_cdn_mac_dict(slot_no)
            if cdn_before_update is False:
                self.failed('CIMC CDN mac list is empty', goto=['cleanup'])
            logger.info('Start updating VIC firmware component')
            if fw_utils_obj.update_vic_firmware(slot_no, vic_fw_image) is not True:
                self.failed('Failed to Update the VIC firmware', goto=['cleanup'])
            logger.info('Fetch CDN info after VIC Update')
            cdn_after_update = vic_obj.cimc_cdn_mac_dict(slot_no)
            if cdn_after_update is False:
                self.failed('CIMC CDN mac list is empty', goto=['cleanup'])
            match = True
            for key in cdn_before_update.keys():
                if key in cdn_after_update.keys():
                    if cdn_before_update[key] != cdn_after_update[key]:
                        logger.error('CDN name Before:' +cdn_before_update[key] + 'After Update: '\
                                      + cdn_after_update[key])
                        match = False
                    else:
                        logger.info('CDN name before update:' +cdn_before_update[key] + \
                                    'After Update:' + cdn_after_update[key])
            if match is True:
                logger.info('CDN Name retained before and after BIOS upgrade')
                self.passed('Test Passed')
            else:
                logger.info('CDN Name failed to retain after BIOS upgrade')
                self.failed('Test Failed')
    @aetest.cleanup
    def cleanup(self, cimc_util_obj, config):
        logger.info('In clenup section of ConfigureModifyDeleteCDNTest')
        vic_obj = VicLib(cimc_util_obj, config)
        for val in self.created_vnic_list:
            slot_no = val.split(' ')[0]
            dev_name = val.split(' ')[1]
            logger.info('Delete vnic {} interface on slot {}'.format(dev_name, slot_no))
            vic_obj.delete_vnic(slot_no, dev_name)
class VerifyCDNInTechSupport(aetest.Testcase):
    @aetest.test
    def Verify_Tech_support_report(self, cimc_util_obj, config):
        '''
        Logical ID: RACK-BIOS-DN-CDN-VIC-022
        Test Case: Check for CDN detail from Tech Support log
        Pass/Fail Criteria: CDN names and its details should appear correctly in Techsupport log
        Author: lakkris2
        '''
        vic_obj = VicLib(cimc_util_obj, config)
        vic_list = config.inventory_detail
        self.created_vnic_list = []
        if cimc_util_obj.set_host_power('on') is False:
            self.failed('Failed to power on host', goto=['cleanup'])
        for vic in vic_list:
            logger.info('vic slot number is: ' + vic.slot_number)
            slot_no = vic.slot_number
            '''creating 2 vNIC interface'''
            dev_list = ['9', '10']
            if create_vnic_interface(self, vic_obj, slot_no, dev_list) is not True:
                self.failed('Failed to create vnic interface', goto=['cleanup'])
        cimc_util_obj.power_cycle_host()
        host_ip = get_host_mgmt_ip(config)
        res = cimc_util_obj.verify_host_up(host_ip, wait_time=400, wait_for_ping_fail=False)
        if res is False:
            logger.warning('Failed to ping the host after host reboot')
        else:
            logger.info("Host name IP pinging successfully")
        out = cimc_util_obj.upload_techsupport_data(protocol='tftp')
        if out is False:
            self.failed('Failed to upload tech-support data', goto=['cleanup'])
        res = cimc_util_obj.validate_cdn_techsupport(config)
        if res is False:
            self.failed('Failed to verify that CDN info consistent across CIMC and VIC exported \
            files', goto=['cleanup'])
        else:
            self.passed('Successfully verified that CDN info consistent across CIMC and VIC config')
        cimc_util_obj.remove_techsupport_file()
    @aetest.cleanup
    def cleanup(self, cimc_util_obj, config):
        logger.info('In clenup section of CDNExportTest')
        vic_obj = VicLib(cimc_util_obj, config)
        for val in self.created_vnic_list:
            slot_no = val.split(' ')[0]
            dev_name = val.split(' ')[1]
            logger.info('Delete vnic {} interface on slot {}'.format(dev_name, slot_no))
            vic_obj.delete_vnic(slot_no, dev_name)
class MaxVnicCDNTest(aetest.Testcase):
    @aetest.test
    def max_vnic_cdn_test(self, cimc_util_obj, config):
        '''
        Logical ID: RACK-BIOS-DN-CDN-VIC-007
        Test Case: Create CDN with max vNIC and OS Reboot Stress
        Pass/Fail Criteria: CDN naming should appearing correcly in CIMC WebUI and in windows OS also
        author: lakkris2
        '''
        vic_list = []
        vic_obj = VicLib(cimc_util_obj, config)
        vic_list = config.inventory_detail
        os_reboot_count = 1 #For OS reboot stress
        if cimc_util_obj.set_host_power('on') is False:
            self.failed('Failed to power on host', goto=['cleanup'])
        logger.info('VIC list are =============>>> ' + str(vic_list))
        test_fail = '0'
        for vic in vic_list:
            logger.info('vic slot number is: ' + vic.slot_number)
            slot_no = vic.slot_number
            out = vic_obj.cimc_cdn_mac_dict(slot_no)
            cdn_name_from_cimc = []
            del cdn_name_from_cimc[:]
            for name in out.values():
                cdn_name_from_cimc.append(name)
            logger.info('CDN name from CIMC are')
            logger.info(cdn_name_from_cimc)
            length_exist_vnic = len(cdn_name_from_cimc)
            logger.info(length_exist_vnic)
            Remaining_vnic = 16-length_exist_vnic
            logger.info('Remaining vnic count: '+ str(Remaining_vnic))
            remain_vnic_list = []
            for val in range(Remaining_vnic):
                remain_vnic_list.append(str(val))

            logger.info('remaining vnics to be created' + str(remain_vnic_list))
            '''creating vNIC interface '''
            self.created_vnic_list = []
            if create_vnic_interface(self, vic_obj, slot_no, remain_vnic_list) is not True:
                self.failed('Failed to create vnic interface', goto=['cleanup'])

            #for dev_list in range(Remaining_vnic):
            #    logger.info('Device list are:' + str(dev_list))
            #    if create_vnic_interface(self, vic_obj, slot_no, str(dev_list)) is not True:
            #        self.failed('Failed to create vnic interface', goto=['cleanup'])
            
            test_fail = '0'
            for power_cycle_cnt in range(os_reboot_count):
                logger.info("System reboot count #: " + str(power_cycle_cnt))
                res = vic_obj.powercycle_and_verify_cdn_on_cimc_and_host(slot_no)
                if res is False:
                    logger.error('CDN name miss match between OS and CIMC after max vnic creation',\
                                 goto=['cleanup'])
                    test_fail = '1'
                else:
                    logger.info('CDN name matched between OS and CIMC after max vnic creation')
        if test_fail == '1':
            self.failed('Test Failed')
        else:
            self.passed('Test Passed')
    @aetest.cleanup
    def cleanup(self, cimc_util_obj, config):
        logger.info('In clenup section of MaxVnicCDNTest')
        vic_obj = VicLib(cimc_util_obj, config)
        for val in self.created_vnic_list:
            slot_no = val.split(' ')[0]
            dev_name = val.split(' ')[1]
            logger.info('Delete vnic {} interface on slot {}'.format(dev_name, slot_no))
            vic_obj.delete_vnic(slot_no, dev_name)
    
class CimcRebootCDNTest(aetest.Testcase):
    @aetest.test
    def verify_cdn_cimc_Reboot(self, cimc_util_obj, config):
        '''
        Logical ID: RACK-BIOS-DN-CDN-VIC-007
        Test Case: To create maximum vNIC
        '''
        logger.info('To Verify CDN after CIMC reboot')
        vic_list = []
        vic_obj = VicLib(cimc_util_obj, config)
        bios_obj = cimc_util_obj.bios_util_obj
        vic_list = config.inventory_detail
        self.created_vnic_list = []
        if cimc_util_obj.set_host_power('on') is False:
            self.failed('Failed to power on host', goto=['cleanup'])
        for vic in vic_list:
            logger.info('vic slot number is: ' + vic.slot_number)
            slot_no = vic.slot_number
            '''creating vNIC interface'''
            dev_list = ['11']
            if create_vnic_interface(self, vic_obj, slot_no, dev_list) is not True:
                self.failed('Failed to create vnic interface', goto=['cleanup'])
            logger.info('Fetch CDN info before cimc reboot')
            cdn_before_reboot = vic_obj.cimc_cdn_mac_dict(slot_no)
            if cdn_before_reboot is False:
                self.failed('CIMC CDN mac list is empty', goto=['cleanup'])
            logger.info('Reboot BMC')
            res = cimc_util_obj.reboot_bmc_and_connect(config)
            if res is not True:
                self.failed('Failed to reboot and connect back', goto=['cleanup'])
            logger.info('Fetch CDN info after CIMC reboot')
            cdn_after_reboot = vic_obj.cimc_cdn_mac_dict(slot_no)
            if cdn_after_reboot is False:
                self.failed('CIMC CDN mac list is empty', goto=['cleanup'])
            match = True
            for key in cdn_before_reboot.keys():
                if key in cdn_after_reboot.keys():
                    if cdn_before_reboot[key] != cdn_after_reboot[key]:
                        logger.error('CDN name Before:' +cdn_before_reboot[key] + \
                                     'After Reboot: ' + cdn_after_reboot[key])
                        match = False
                    else:
                        logger.info('CDN name before reboot:' +cdn_before_reboot[key] + \
                                    'After Reboot:' + cdn_after_reboot[key])
            if match is True:
                logger.info('CDN Name retained before and after CIMC reboot')
                self.passed('Test Passed')
            else:
                logger.info('CDN Name failed to retain after CIMC reboot')
                self.failed('Test Failed')
    @aetest.cleanup
    def cleanup(self, cimc_util_obj, config):
        logger.info('In clenup section of CimcRebootCDNTest')
        vic_obj = VicLib(cimc_util_obj, config)
        for val in self.created_vnic_list:
            slot_no = val.split(' ')[0]
            dev_name = val.split(' ')[1]
            logger.info('Delete vnic {} interface on slot {}'.format(dev_name, slot_no))
            vic_obj.delete_vnic(slot_no, dev_name)
class DisableCDNTest(aetest.Testcase):
    @aetest.test
    def disable_cdn_test(self, cimc_util_obj, config):
        '''
        Logical ID: RACK-BIOS-DN-CDN-VIC-010
        Test Case: To Verify CDN token Disabled
        Pass/Fail: Existing CDN named should be retained and
                    CDN name should not get changed.
        '''
        vic_list = []
        vic_obj = VicLib(cimc_util_obj, config)
        vic_list = config.inventory_detail
        self.created_vnic_list = []
        if cimc_util_obj.set_host_power('on') is False:
            self.failed('Failed to power on host', goto=['cleanup'])
        bios_obj = cimc_util_obj.bios_util_obj
        bios_token = 'cdnEnable'
        token_new_value = 'Disabled'
        host_ip = get_host_mgmt_ip(config)
        for vic in vic_list:
            logger.info('vic slot number is: ' + vic.slot_number)
            slot_no = vic.slot_number
            '''creating vNIC interface'''
            dev_list = ['12']
            if create_vnic_interface(self, vic_obj, slot_no, dev_list) is not True:
                self.failed('Failed to create vnic interface', goto=['cleanup'])
            logger.info('Fetch VIC and CDN info before disabling the CDN token')
            cdn_before_disable = vic_obj.cimc_cdn_mac_dict(slot_no)
            if cdn_before_disable is False:
                self.failed('CIMC CDN mac list is empty', goto=['cleanup'])

            logger.info('Disable the Bios CDN token')
            if bios_obj.set_bios_token_value(bios_token, token_new_value) is not True:
                self.failed('Failed to set bios token value', goto=['cleanup'])
            '''Wait for host to reboot'''
            res = cimc_util_obj.verify_host_up(host_ip, wait_for_ping_fail=False, wait_time=400)
            if res is not True:
                self.failed('Failed to ping host', goto=['cleanup'])

            logger.info('Fetch VIC and CDN info after disabling CDN token')
            cdn_after_disbale = vic_obj.cimc_cdn_mac_dict(slot_no)
            if cdn_after_disbale is False:
                self.failed('CIMC CDN mac list is empty', goto=['cleanup'])
            match = True
            for key in cdn_before_disable.keys():
                if key in cdn_after_disbale.keys():
                    if cdn_before_disable[key] != cdn_after_disbale[key]:
                        logger.error('CDN name Before:' +cdn_before_disable[key] + \
                                     'After Disable: ' + cdn_after_disbale[key])
                        match = False
                    else:
                        logger.info('CDN name before reboot:' +cdn_before_disable[key] + \
                                    'After Disable:' + cdn_after_disbale[key])
            if match is True:
                logger.info('CDN Name retained before and after disable of bios CDN token')
                self.passed('Test Passed')
            else:
                logger.info('Failed to retain Vnic after disabling CDN bios token')
                self.failed('Test Failed')
    @aetest.cleanup
    def cleanup(self, cimc_util_obj, config):
        logger.info('In clenup section of CimcRebootCDNTest')
        vic_obj = VicLib(cimc_util_obj, config)
        for val in self.created_vnic_list:
            slot_no = val.split(' ')[0]
            dev_name = val.split(' ')[1]
            logger.info('Delete vnic {} interface on slot {}'.format(dev_name, slot_no))
            vic_obj.delete_vnic(slot_no, dev_name)
class LoadBiosDefaultTest(aetest.Testcase):
    @aetest.test
    def load_default_test(self, cimc_util_obj, config):
        '''
        Logical ID: RACK-BIOS-DN-CDN-VIC-011
        Test Case: Check CDN by setting to BIOS Load default
        Pass/Fail Criteria: 1. CDN setting should go to Defaut Value Disabled
                    2. Existing CDN Names should get retain
        author: lakkris2
        '''
        vic_list = []
        vic_obj = VicLib(cimc_util_obj, config)
        vic_list = config.inventory_detail
        self.created_vnic_list = []
        if cimc_util_obj.set_host_power('on') is False:
            self.failed('Failed to power on host', goto=['cleanup'])
        bios_obj = cimc_util_obj.bios_util_obj
        bios_token = 'cdnEnable'
        cdn_token_enable = 'Enabled'
        scope = 'advanced'
        host_ip = get_host_mgmt_ip(config)
        bios_obj.set_bios_token_value(bios_token, cdn_token_enable)
        token_val = bios_obj.get_bios_token_value(bios_token)
        if token_val == cdn_token_enable:
            logger.info('Successfully verified that CDN token can be enabled from CIMC')
        else:
            self.failed('Failed to verify that CDN token,\
                Expected is:' + cdn_token_enable + ' But got as: ' + token_val, goto=[cleanup])
        res = cimc_util_obj.verify_host_up(host_ip, wait_for_ping_fail=False)
        if res is False:
            logger.warning('Failed to ping the host after host reboot')
        else:
            logger.info("Host name IP pinging successfully")
        test_fail = '0'
        for vic in vic_list:
            logger.info('vic slot number is: ' + vic.slot_number)
            slot_no = vic.slot_number
            '''creating vNIC interface'''
            dev_list = ['13']
            if create_vnic_interface(self, vic_obj, slot_no, dev_list) is not True:
                self.failed('Failed to create vnic interface', goto=['cleanup'])
            logger.info('Fetch VIC and CDN info before bios load defaults')
            cdn_before_default = vic_obj.cimc_cdn_mac_dict(slot_no)
            if cdn_before_default is False:
                self.failed('CIMC CDN mac list is empty', goto=['cleanup'])
            '''performing Bios default '''
            if bios_obj.load_bios_defaults() is not True:
                self.failed('Failed to run bios defaults', goto=['cleanup'])
            res = cimc_util_obj.verify_host_up(host_ip, wait_for_ping_fail=False, wait_time=400)
            if res is False:
                logger.warning('Failed to ping the host after host reboot')
            else:
                logger.info("Host name IP pinging successfully")
            '''After Bios Default checking CDN name and CDN setting '''
            out = bios_obj.get_bios_token_value(bios_token)
            if "Enabled" in out:
                self.passed("CDN token Enabled after Loading Default bios setting")
            else:
                self.failed('Failed to Set CDN to Enabled after bios default, but got as:' + out)
            logger.info('Fetch VIC and CDN info after bios load default')
            cdn_after_default = vic_obj.cimc_cdn_mac_dict(slot_no)
            if cdn_after_disbale is False:
                self.failed('CIMC CDN mac list is empty', goto=['cleanup'])
            test_fail = '0'
            host_dict = vic_obj.host_cdn_mac_dict(cimc_util_obj.host_handle, 'biosdevname -d')
            cdn_name_from_host = []
            for cdn_name_from_host1 in host_dict.values():
                cdn_name_from_host.append(cdn_name_from_host1)
                if "LOMPort1" and "LOMPort2" not in cdn_name_from_host:
                    logger.info("LOMPort1 and LOMPort2 available in Host OS, when CDN Enabled")
                else:
                    logger.error('LOMPort1 and LOMPort2 are not available in Host OS, when CDN Enabled')
                    test_fail = '1'
            match = True
            for key in cdn_before_default.keys():
                if key in cdn_after_default.keys():
                    if cdn_before_default[key] != cdn_after_default[key]:
                        logger.error('CDN name Before:' +cdn_before_default[key] + \
                                     'After Disable: ' + cdn_after_default[key])
                        match = False
                    else:
                        logger.info('CDN name before reboot:' +cdn_before_default[key] + \
                                    'After Disable:' + cdn_after_default[key])
            if match is True:
                logger.info('CDN Name retained before and after bios load default')
            else:
                logger.info('Failed to retain Vnic after bios load default')
                test_fail = '1'
            mac_match = True
            for mac in cdn_before_default.values():
                if mac in cdn_after_default.values():
                    if cdn_before_default[mac] != cdn_after_default[mac]:
                        logger.error('CDN name Before:' +cdn_before_default[mac] + \
                                     'After Disable: ' + cdn_after_default[mac])
                        mac_match = False
                    else:
                        logger.info('CDN name before reboot:' +cdn_before_default[mac] + \
                                    'After Disable:' + cdn_after_default[mac])
            if mac_match is True:
                logger.info('CDN Name retained before and after bios load default')
            else:
                logger.info('Failed to retain Vnic after bios load default')
                test_fail = '1'
        if test_fail == '1':
            self.failed('Test case failed')
        else:
            self.passed('Test case passed')
    @aetest.cleanup
    def cleanup(self, cimc_util_obj, config):
        logger.info('In clenup section of CimcRebootCDNTest')
        vic_obj = VicLib(cimc_util_obj, config)
        for val in self.created_vnic_list:
            slot_no = val.split(' ')[0]
            dev_name = val.split(' ')[1]
            logger.info('Delete vnic {} interface on slot {}'.format(dev_name, slot_no))
            vic_obj.delete_vnic(slot_no, dev_name)
class ConfigModifyDeleteCDNTestOnWindows(aetest.Testcase):
    #@aetest.test
    def configure_modify_delete_cdn(self, cimc_util_obj, config):
        '''
        Logical ID: RACK-BIOS-DN-CDN-VIC-004
                    RACK-BIOS-DN-CDN-VIC-005
                    RACK-BIOS-DN-CDN-VIC-006
        Test Case: To Configure CDN for vNIC
                    To Modify CDN for vNIC
                    To Delete CDN for vNIC
        '''
        vic_list = []
        vic_obj = VicLib(cimc_util_obj, config)
        vic_list = config.inventory_detail
        self.created_vnic_list = []
        if cimc_util_obj.set_host_power('on') is False:
            self.failed('Failed to power on host', goto=['next_tc'])
        for vic in vic_list:
            logger.info('vic slot number is: ' + vic.slot_number)
            slot_no = vic.slot_number
            logger.info('Creating vNIC interface with unique name and verify')
            for dev in ['one_', 'two_']:
                dev_name = 'eth_dev_'+dev+str(i)
                cdnname = 'cdn_'+dev_name
                res = vic_obj.create_vnic(slot_no, dev_name, cdn_name=cdnname)
                if res is not True:
                    logger.error('Failed to create vNIC interface')
                    self.failed('Failed to create vNIC', goto=['cleanup'])
                else:
                    self.created_vnic_list.append(dev_name)
                    logger.info('Successfully created vNIC with device name: ' + dev_name)
            res1 = vic_obj.powercycle_and_verify_cdn_on_windows(slot_no)
            # Windows requires driver re-installation on every modification to vNIC CDN
            # Hence commenting out modify delete verification part on windows side.
            '''
            logger.info('Modify the CDN name for vNIC and verify')
            for x, dev_name in enumerate(self.created_vnic_list, 1):
                if vic_obj.modify_vnic_properties(slot_no, dev_name, 'CDN', 'modified_cdn_'+str(x)) is not True:
                    logger.warning('Failed to modify the CDN name attribute of vNIC')
            res2 = vic_obj.powercycle_and_verify_cdn_on_windows(slot_no)
            logger.info('Deleting the vNIC interface and verify')
            for dev in created_vnic_list:
                if vic_obj.delete_vnic(slot_no, dev) != True:
                    logger.warning('Failed to delete vNIC ethernet interface ' + dev)
            res3 = vic_obj.powercycle_and_verify_cdn_on_windows(slot_no)
            '''
            if res1 == False:
                self.failed('Test cases failed')
            else:
                self.passed('Test Case Passed')
    #@aetest.cleanup
    def cleanup(self, cimc_util_obj, config):
        logger.info('In clenup section of BiosUpdateCdnTest')
        vic_obj = VicLib(cimc_util_obj, config)
        for val in self.created_vnic_list:
            slot_no = val.split(' ')[0]
            dev_name = val.split(' ')[1]
            logger.info('Delete vnic {} interface on slot {}'.format(dev_name, slot_no))
            vic_obj.delete_vnic(slot_no, dev_name)
class CommonCleanUp(Cleanup):
    @aetest.subsection
    def cleanup(self, mgmt_handle):
        super(CommonCleanUp, self).clean_everything(mgmt_handle)
    