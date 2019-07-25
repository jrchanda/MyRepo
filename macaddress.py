import os
import re

import logging
import common_utils

from ats import aetest
from common_test import Setup, Cleanup
from smbios_lib import SmbiosLib
from SystemDetailsCollector_lib import SystemDetailsCapture

logger = logging.getLogger(__name__)
std_dir = "/data/software/capture_system_details/"


class CommonSetup(Setup):
    '''
    Common Setup section which connects to CIMC
    '''
    @aetest.subsection
    def connect(self, testscript, testbed_name):
        super(CommonSetup, self).connect(testscript, testbed_name)


class MacVerify(aetest.Testcase):

    def slot_cimc_cli(self, cimc_util_obj):

        mgmt_handle = cimc_util_obj.handle

        output = mgmt_handle.execute_cmd_list(
            'top', 'scope chassis', 'show network-adapter detail')
        slot_id = []
        logger.info("Output......" + output)
        for block in output.split("---")[1:]:
            slot = re.search('Slot:*\s+([^\r\n]+)', block).group(1)
            slot_id.append(slot)
            #interface = re.search('NoOfInterfaces:*\s+([^\r\n]+)', block).group(1)
            logger.info("SLot info ...." + slot)
        return slot_id

    def mac_cimc(self, cimc_util_obj, slot_id):

        mgmt_handle = cimc_util_obj.handle
        for val in slot_id:
            output = mgmt_handle.execute_cmd_list(
                'scope network-adapter ' + str(val), 'show mac-list detail')
            mac_address = []
            for block in output.split("---")[1:]:
                mac = re.search('MacAddress:*\s+([^\r\n]+)', block).group(1)
                mac_address.append(mac.lower())
                logger.info("cimc mac info...." + str(mac_address))
        return mac_address

    def mac_interface(self, cimc_util_obj):

        mgmt_handle = cimc_util_obj.handle
        output = mgmt_handle.execute_cmd_list('top', 'scope chassis', 'show network-adapter detail')
        interface_id = []
        for block in output.split("---")[1:]:
            interface = re.search('NoOfInterfaces:*\s+([^\r\n]+)', block).group(1)
            interface_id.append(interface)
            logger.info("Interface info..." + str(interface_id))
        return interface_id

    def mac_linux(self, cimc_util_obj, config):

        #cimc_util_obj.verify_host_up(hostname=host_os_ip, wait_for_ping_fail=False, wait_time=600)

        host_ip = common_utils.get_host_mgmt_ip(config)
        host_ping_status = cimc_util_obj.verify_host_up(
            hostname=host_ip, wait_for_ping_fail=False, wait_time=30)
        if host_ping_status is True:
            logger.info("Host OS is pinging  ...")
        else:
            boot_order_obj = BootOrder(cimc_util_obj, config)
            output = boot_order_obj.set_boot_order_HDD()
            if output == True:
                host_ping_status = cimc_util_obj.verify_host_up(
                    hostname=host_ip, wait_for_ping_fail=False, wait_time=600)
                if host_ping_status is True:
                    logger.info("Host OS is pinging  ...")
                else:
                    logger.error("ERROR :Host OS is not pinging \
                                ,after setting the boot order to HDD and retrying ...")
                    logger.error(
                        "Testcase failed .... since Unabke to boot to OS")
                    return False
        os_handle = cimc_util_obj.host_handle
        output = []
        os_handle.connect()
        output = os_handle.execute_cmd('ifconfig | grep -o -E "([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}"')
        logger.info("OS mac info", str(output))
        return output.lower()

    @aetest.test
    def verify_mac(self, cimc_util_obj, config):
        slot_id = self.slot_cimc_cli(cimc_util_obj)
        mac_address_list = self.mac_cimc(cimc_util_obj, slot_id)
        smbios_obj = SmbiosLib()
        host_os_ip = smbios_obj.get_host_mgmt_ip(config)
        os_mac_list = self.mac_linux(cimc_util_obj, config)
        if os_mac_list is False:
            self.failed("Failed to ping host")
        interface_list = self.mac_interface(cimc_util_obj)
        logger.info("cimc mac info......." + str(mac_address_list))
        logger.info("OS mac info......." + str(os_mac_list))
        no_of_mac = len(mac_address_list)
        interface_list = map(int, interface_list)
        no_of_int = sum(interface_list)
        logger.info("cimc mac info......." + str(no_of_mac))
        logger.info("Int mac info......." + str(no_of_int))
        test = 0
        for mac in mac_address_list:
            if mac in os_mac_list:
                logger.info(mac + ": mac address found in the OS")
                test = 1
            else:
                self.failed(mac + ": is not found in the OS")

        if test == 1 and no_of_int == no_of_mac:
            logger.info("Mac Adddress is Passed")
        else:
            self.failed("mac Address is Failed")


    @aetest.test
    def cimc_mac_compare(self, cimc_util_obj, testbed_name, config):
        system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        #cimc_cli_handle = cimc_util_obj.handle
        # out of scope main
        logger.info("Inside the CIMCMAccaddressCapture")
        # generate thw slot ID list
        file_contents = "MAC List :"
        slot_id = system_capture_object.get_slot_cimc()
        logger.info(slot_id)
        # append the MAC list to the filecontents
        for slot in slot_id:
            output = system_capture_object.get_mac_cimc(slot_id)
            file_contents = file_contents + str(output)

        filename_latest = "CIMC_MAC_inv_info_latest_" + testbed_name
        file_path_to_save = std_dir + testbed_name + "_1"
        file_creation_status = system_capture_object.generate_file_from_output(
            file_contents, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # check with the file std id avialbale
        test_dir = testbed_name + "_std_1"
        file_name_std = "CIMC_MAC_inv_info_std_" + testbed_name
        file_path_std = std_dir + "/" + test_dir + "/" + file_name_std
        logger.info("....." + str(os.path.exists(file_path_std)))
        if os.path.exists(file_path_std):
            logger.info(file_name_std + "is available for comparison")
            file_diff_status = system_capture_object.file_compare(
                file_path_std, filename_latest)
            if file_diff_status is True:
                self.passed("Testcase Passed : no difference between " +
                            file_name_std + " and " + filename_latest)
            else:
                logger.error(
                    "Testcase failed : There is  difference in tokens " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed : There difference in tokens " +
                            file_name_std + " and " + filename_latest)
        else:
            logger.error(
                "Static File is not found in this system at" + file_path_std)
            self.failed("Testcase failed : STD file")
