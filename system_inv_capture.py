from _ast import IsNot
from _collections import defaultdict
import logging
import os
import subprocess
import re
from pip.utils import file_contents
from SystemDetailsCollector_lib import SystemDetailsCapture
from ats import aetest
from ats import easypy
import cimc_utils
from common_test import Setup, Cleanup
from smbios_lib import SmbiosLib


# Get your logger for your script
logger = logging.getLogger(__name__)

std_dir = "/data/software/capture_system_details/"


class CommonSetup(Setup):
    '''
    Commom Stup
    '''
    @aetest.subsection
    def connect(self, testscript, testbed_name):
        super(CommonSetup, self).connect(testscript, testbed_name)
        
    @aetest.subsection
    def inital_setup(self,cimc_util_obj,config):
        global system_capture_object
        system_capture_object = SystemDetailsCapture(cimc_util_obj, config)    


class SystemInventoryCaptureSTD(aetest.Testcase):
    '''
    Class for capturing System Inventoty Capture
    '''

    @aetest.test
    def cpu_info_capture(self,  testbed_name):
        '''
        CPU Info Capture
        '''
        # Connect host to get the output
        cmd = "cat /proc/cpuinfo | grep -E 'processor|model|core|flag'"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # ## if truue generate the file
        filename = "CPU_info_std_" + testbed_name
        file_path_to_save = std_dir + testbed_name + "_1"
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # ## copy the file to the location std_dir
        test_dir = testbed_name + "_std_1"
        path_to_copy = std_dir + test_dir + '/'
        file_copy_status = system_capture_object.copy_file_to_share(
            filename, path_to_copy)
        if file_copy_status is False:
            self.failed(
                "Error in copying the file to location :" + path_to_copy)

    @aetest.test
    def mem_info_capture(self,  testbed_name):
        '''
        Capture Mem Info to the default location
        '''
        # Connect host to get the output
        cmd = "cat /proc/meminfo | grep -E 'MemTotal'"
        # create an object for Sysftem capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # # convert Kb to GB approximatly GB
        match = re.search("MemTotal:\s+([^\r\n]+)", output).group(1)
        total_memory_size = match[:5]
        file_content = "MemTotal: " + total_memory_size + " Mb"
        # ## if truue generate the file
        filename = "Mem_info_std_" + testbed_name
        file_path_to_save = std_dir + testbed_name + "_1"
        file_creation_status = system_capture_object.generate_file_from_output(
            file_content, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # ## copy the file to the location std_dir
        test_dir = testbed_name + "_std_1"
        path_to_copy = std_dir + test_dir + '/'
        file_copy_status = system_capture_object.copy_file_to_share(
            filename, path_to_copy)
        if file_copy_status is False:
            self.failed(
                "Error in copying the file to location :" + path_to_copy)

    @aetest.test
    def dmidecode_info_capture(self,  testbed_name):
        '''
        Dmidecode Info capture
        '''
        # Connect host to get the output
        cmd = "dmidecode -q"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # # DMIDecode convserion

        filename = "Dmidecode_info_std_" + testbed_name
        file_path_to_save = std_dir + testbed_name + "_1"
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # ## copy the file to the location std_dir
        test_dir = testbed_name + "_std_1"
        path_to_copy = std_dir + test_dir + '/'
        file_copy_status = system_capture_object.copy_file_to_share(
            filename, path_to_copy)
        if file_copy_status is False:
            self.failed(
                "Error in copying the file to location :" + path_to_copy)

    @aetest.test
    def lspci_dev_info_capture(self,  testbed_name):
        '''
        Capture LSPCI info
        '''
        # Connect host to get the output
        cmd = "lspci -mn"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # # DMIDecode convserion
        filename = "Lspci_dev_info_std_" + testbed_name
        file_path_to_save = std_dir + testbed_name + "_1"
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # ## copy the file to the location std_dir
        test_dir = testbed_name + "_std_1"
        path_to_copy = std_dir + test_dir + '/'
        file_copy_status = system_capture_object.copy_file_to_share(
            filename, path_to_copy)
        if file_copy_status is False:
            self.failed(
                "Error in copying the file to location :" + path_to_copy)

    @aetest.test
    def lspci_info_capture(self,  testbed_name):
        '''
        lspci
        '''
        # Connect host to get the output
        cmd = "lspci -vvvvvvvxxbDkq"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd,cmd_wait_time=120)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # # DMIDecode convserion
        filename = "Lspci_full_info_std_" + testbed_name
        file_path_to_save = std_dir + testbed_name + "_1"
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # ## copy the file to the location std_dir
        test_dir = testbed_name + "_std_1"
        path_to_copy = std_dir + test_dir + '/'
        file_copy_status = system_capture_object.copy_file_to_share(
            filename, path_to_copy)
        if file_copy_status is False:
            self.failed(
                "Error in copying the file to location :" + path_to_copy)

    @aetest.test
    def mac_addr_info_capture(self,  testbed_name):
        '''
        Mac Addr Info capture
        '''
        # Connect host to get the output
        cmd = "ifconfig | grep -E 'HWaddr'"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # # DMIDecode convserion
        filename = "MAC_info_std_" + testbed_name
        file_path_to_save = std_dir + testbed_name + "_1"
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # ## copy the file to the location std_dir
        test_dir = testbed_name + "_std_1"
        path_to_copy = std_dir + test_dir + '/'
        file_copy_status = system_capture_object.copy_file_to_share(
            filename, path_to_copy)
        if file_copy_status is False:
            self.failed(
                "Error in copying the file to location :" + path_to_copy)

    @aetest.test
    def boot_order_capture(self, cimc_util_obj, testbed_name):
        '''
        Boot order capture
        '''
        # ## connect to CIMC
        # CIMC connect handle is already availabke in the common setup
        # ## execute cmd
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        cimc_cli_handle = cimc_util_obj.handle
        # cmd_list = ['top','scope bios','show actual','show actual-boot-order detail']
        output = cimc_cli_handle.execute_cmd_list(
            'top', 'scope bios', 'show actual', 'show actual-boot-order detail', wait_time=20)
        logger.info(str(output))
        # parse the output
        lines = output.split("\n")
        file_contents = "Boot device : \n\r"
        for line in lines:
            line = line.strip()
            logger.info("Line ...." + str(line))
            match_string = "DeviceName:\s+([^\n\r]+)"
            match_value = re.search(match_string, line)
            if match_value is not None:
                logger.info("Match value...." + match_value.group(1))
                boot_dev_name = match_value.group(1)
                file_contents = file_contents + boot_dev_name + "\n\r"
        # ## save the output to the file
        filename = "Bootorder_info_std_" + testbed_name
        file_path_to_save = std_dir + testbed_name + "_1"
        file_creation_status = system_capture_object.generate_file_from_output(
            file_contents, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # ## copy the file to the location std_dir
        test_dir = testbed_name + "_std_1"
        path_to_copy = std_dir + test_dir + '/'
        file_copy_status = system_capture_object.copy_file_to_share(
            filename, path_to_copy)
        if file_copy_status is False:
            self.failed(
                "Error in copying the file to location :" + path_to_copy)

    @aetest.test
    def bios_token_capture(self, cimc_util_obj, testbed_name):
        '''
        '''
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        cimc_cli_handle = cimc_util_obj.handle

        # ## out of scope main
        output1 = cimc_cli_handle.execute_cmd_list(
            'top', 'scope bios', 'scope main', 'show detail')
        output1 = output1.split("---")
        output2 = cimc_cli_handle.execute_cmd_list(
            'top', 'scope bios', 'scope server-management', 'show detail')
        output2 = output2.split("---")
        output3 = cimc_cli_handle.execute_cmd_list(
            'top', 'scope bios', 'scope advanced', 'show detail')
        output3 = output3.split("---")
        file_contents = output1[1] + "\n\r" + output2[1] + "\n\r" + output3[1]
        logger.info(str(file_contents))
        # ## generate the file
        filename = "BIOS_Tokens_info_std_" + testbed_name
        file_path_to_save = std_dir + testbed_name + "_1"
        file_creation_status = system_capture_object.generate_file_from_output(
            file_contents, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # ## copy the file to the location std_dir
        test_dir = testbed_name + "_std_1"
        path_to_copy = std_dir + test_dir + '/'
        file_copy_status = system_capture_object.copy_file_to_share(
            filename, path_to_copy)
        if file_copy_status is False:
            self.failed(
                "Error in copying the file to location :" + path_to_copy)

    @aetest.test
    def e820_info_capture(self,  testbed_name):
        '''
        '''
        # Connect host to get the output
        cmd = "dmesg | grep -E 'e820|E820'"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        output = re.sub(
            r'\[.*?\]', "", output, flags=re.IGNORECASE)    
        # ## if truue generate the file
        filename = "E820_info_std_" + testbed_name
        file_path_to_save = std_dir + testbed_name + "_1"
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # ## copy the file to the location std_dir
        test_dir = testbed_name + "_std_1"
        path_to_copy = std_dir + test_dir + '/'
        file_copy_status = system_capture_object.copy_file_to_share(
            filename, path_to_copy)
        if file_copy_status is False:
            self.failed(
                "Error in copying the file to location :" + path_to_copy)

    @aetest.test
    def cimc_inv_capture(self, cimc_util_obj, testbed_name):
        '''
        '''
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        cimc_cli_handle = cimc_util_obj.handle
        # ## out of scope main
        file_contents = cimc_cli_handle.execute_cmd_list(
            'top', 'scope chassis', 'inventory-all')
        logger.info(str(file_contents))
        # ## generate the file
        filename = "CIMC_inv_info_std_" + testbed_name
        file_path_to_save = std_dir + testbed_name + "_1"
        file_creation_status = system_capture_object.generate_file_from_output(
            file_contents, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # ## copy the file to the location std_dir
        test_dir = testbed_name + "_std_1"
        path_to_copy = std_dir + test_dir + '/'
        file_copy_status = system_capture_object.copy_file_to_share(
            filename, path_to_copy)
        if file_copy_status is False:
            self.failed(
                "Error in copying the file to location :" + path_to_copy)

    @aetest.test
    def cimc_mac_address_capture(self, testbed_name):
        '''
        Capture MAc address info the file
        '''
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        # ## out of scope main
        logger.info("Inside the CIMCMAccaddressCapture")
        # ## generate thw slot ID list
        file_contents = "MAC List :"
        slot_id = system_capture_object.get_slot_cimc()
        logger.info(slot_id)
        # ## append the MAC list to the filecontents
        for slot in slot_id:
            output = system_capture_object.get_mac_cimc(slot)
            file_contents = file_contents + str(output)

        filename = "CIMC_MAC_inv_info_std_" + testbed_name
        file_path_to_save = std_dir + testbed_name + "_1"
        file_creation_status = system_capture_object.generate_file_from_output(
            file_contents, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # ## copy the file to the location std_dir
        test_dir = testbed_name + "_std_1"
        path_to_copy = std_dir + test_dir + '/'
        file_copy_status = system_capture_object.copy_file_to_share(
            filename, path_to_copy)
        if file_copy_status is False:
            self.failed(
                "Error in copying the file to location :" + path_to_copy)

    @aetest.test
    def usb_info_capture(self,  testbed_name):
        '''
        CPU Info Capture
        '''
        # Connect host to get the output
        cmd = "lsusb"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # ## if truue generate the file
        filename = "usb_info_std_" + testbed_name
        file_path_to_save = std_dir + testbed_name + "_1"
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # ## copy the file to the location std_dir
        test_dir = testbed_name + "_std_1"
        path_to_copy = std_dir + test_dir + '/'
        file_copy_status = system_capture_object.copy_file_to_share(
            filename, path_to_copy)
        if file_copy_status is False:
            self.failed(
                "Error in copying the file to location :" + path_to_copy)

    @aetest.test
    def com_port_info_capture(self,  testbed_name):
        '''
        CPU Info Capture
        '''
        # Connect host to get the output
        cmd = "dmesg | grep serial"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        var = re.findall(r'(serial+\d+:.*)?\(', output)
        output = "\n".join(var)
        # ## if truue generate the file
        filename = "com_port_info_std_" + testbed_name
        file_path_to_save = std_dir + testbed_name + "_1"
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # ## copy the file to the location std_dir
        test_dir = testbed_name + "_std_1"
        path_to_copy = std_dir + test_dir + '/'
        file_copy_status = system_capture_object.copy_file_to_share(
            filename, path_to_copy)
        if file_copy_status is False:
            self.failed(
                "Error in copying the file to location :" + path_to_copy)


class SystemInventoryCaptureBeforeUpdate(aetest.Testcase):
    '''
    Class captures MAC addres info after the HUU update
    '''
    logger.info("Start of the class Inv Capture")

    @aetest.test
    def cpu_info_capture(self,  testbed_name):
        '''
        Collects the CPU info capture after HUU update
        '''
        # Connect host to get the output
        cmd = "cat /proc/cpuinfo | grep -E 'processor|model|core|flag'"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # if truue generate the file
        filename = "CPU_info_before_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def mem_info_capture(self,  testbed_name):
        '''
        Capture the Mem info after HUU update
        '''
        # Connect host to get the output
        cmd = "cat /proc/meminfo | grep -E 'MemTotal'"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # convert Kb to GB approximatly GB
        match = re.search("MemTotal:\s+([^\r\n]+)", output).group(1)
        total_memory_size = match[:5]
        file_content = "MemTotal: " + total_memory_size + " Mb"
        # if truue generate the file
        filename = "Mem_info_before_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            file_content, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def dmidecode_info_capture(self,  testbed_name):
        '''
        Capture DMIdecode after the update
        '''
        # Connect host to get the output
        cmd = "dmidecode -q"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # DMIDecode convserion
        filename = "Dmidecode_info_before_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def lspci_dev_info_capture(self,  testbed_name):
        '''
        LSPCI dev capture
        '''
        # Connect host to get the output
        cmd = "lspci -mn"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # DMIDecode convserion
        filename = "Lspci_dev_info_before_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def lspci_info_capture(self,  testbed_name):
        '''
        LSPCI info capture
        '''
        # Connect host to get the output
        #cmd = "lspci -vvvvvvvxxbDkq | grep -E 'PCI bridge|Control|Status|Latency|Bus|Secondary status|BridgeCtl|Capabilities|DevCtl|DevSta|LnkCap|LnkCtl|RootCtl|'"
        cmd = "lspci -vvvvvvvxxbDkq | grep -E 'Device|controller|bridge|periphera|DevSta|LnkCap|LnkCtl|LnkSta|IRQ|Bus|slot'"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd,cmd_wait_time=120)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # DMIDecode convserion
        filename = "Lspci_full_info_before_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def mac_sddr_info_capture(self,  testbed_name):
        '''
        CApture MAC address
        '''
        # Connect host to get the output
        #cmd = "lspci -vvvvvvvxxbDkq | grep -E 'PCI bridge|Control|Status|Latency|Bus|Secondary status|BridgeCtl|Capabilities|DevCtl|DevSta|LnkCap|LnkCtl|RootCtl|'"
        cmd = "ifconfig | grep -E 'HWaddr'"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # DMIDecode convserion
        filename = "MAC_info_before_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def e820_info_capture(self,  testbed_name):
        '''
        Capture E820 info
        '''
        # Connect host to get the output
        cmd = "dmesg | grep -E 'e820|E820'"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        output = re.sub(
            r'\[.*?\]', "", output, flags=re.IGNORECASE)    
        # if truue generate the file
        filename = "E820_info_before_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def boot_order_capture(self, cimc_util_obj, testbed_name):
        '''
        Capture boot order info
        '''
        # connect to CIMC
        # CIMC connect handle is already availabke in the common setup
        # execute cmd
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        cimc_cli_handle = cimc_util_obj.handle
        #cmd_list = ['top','scope bios','show actual','show actual-boot-order detail']
        output = cimc_cli_handle.execute_cmd_list(
            'top', 'scope bios', 'show actual', 'show actual-boot-order detail', wait_time=20)
        # parse the output
        lines = output.split("\n")
        file_contents = "Boot device : \n\r"
        for line in lines:
            line = line.strip()
            logger.info("Line ...." + str(line))
            match_string = "DeviceName:\s+([^\n\r]+)"
            match_value = re.search(match_string, line)
            if match_value is not None:
                logger.info("Match value...." + match_value.group(1))
                boot_dev_name = match_value.group(1)
                file_contents = file_contents + boot_dev_name + "\n\r"
        # save the output to the file
        filename = "Bootorder_info_before_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            file_contents, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def bios_token_capture(self, cimc_util_obj, testbed_name):
        '''
        Capture BIOS token values
        '''
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        cimc_cli_handle = cimc_util_obj.handle

        # out of scope main
        output1 = cimc_cli_handle.execute_cmd_list(
            'top', 'scope bios', 'scope main', 'show detail')
        output1 = output1.split("---")
        output2 = cimc_cli_handle.execute_cmd_list(
            'top', 'scope bios', 'scope server-management', 'show detail')
        output2 = output2.split("---")
        output3 = cimc_cli_handle.execute_cmd_list(
            'top', 'scope bios', 'scope advanced', 'show detail')
        output3 = output3.split("---")
        file_contents = output1[1] + "\n\r" + output2[1] + "\n\r" + output3[1]
        logger.info(str(file_contents))
        # generate the file
        filename = "BIOS_Tokens_info_before_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            file_contents, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def cimc_inv_capture(self, cimc_util_obj, testbed_name):
        '''
        Capture CIMC Inv
        '''
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        cimc_cli_handle = cimc_util_obj.handle
        # out of scope main
        file_contents = cimc_cli_handle.execute_cmd_list(
            'top', 'scope chassis', 'inventory-all')
        logger.info(str(file_contents))
        # generate the file
        filename = "CIMC_inv_info_before_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            file_contents, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def mrc_out_capture(self, cimc_util_obj, testbed_name, config):
        '''
        MRC info capture after update
        '''
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        # connect to CMIC debug shell
        cimc_debug_handle = cimc_util_obj.telnet_handle
        cimc_debug_handle.connect_to_mgmnt()
        # change the prompt to linux shell
        prompt = 'linuxMode'
        cimc_debug_handle.set_bmc_serial_mode(prompt)
        # execute the command for grep the MRCOUt
        platform_type = config.mgmtdetail.platform_series
        if platform_type == 'M5':
            cmd = "cd /mnt/jffs2/BIOS/bt"
            cmd2 = "cat MrcOut"
            cmd3 = "cat MrcOut | grep -E 'Socket|Effective Memory|Total Memory|Memory Speed|Mem| \
                                   Memory Voltage|ECC|CAP|Scrub|Mode|Policy|Revision|Channel' >> mrc.txt"
        else:
            cmd = "cd /var/nuova/BIOS"
            cmd2 = "cat MrcOut.txt"
            cmd3 = "cat MrcOut.txt | grep -E 'Socket|Effective Memory|Total Memory|Memory Speed|Mem| \
                                   Memory Voltage|ECC|CAP|Scrub|Mode|Policy|Revision|Channel' >> mrc.txt"

        output = cimc_debug_handle.execute_cmd_serial(cmd)
        cmd = "ls"
        output = cimc_debug_handle.execute_cmd_serial(cmd)
        #cmd = "cat MrcOut.txt"
        output = cimc_debug_handle.execute_cmd_serial(cmd2)
        logger.info(" ####### Out of the MRC ############")
        logger.info(output)
        #cmd = "cat MrcOut.txt | grep -E 'Socket|Effective Memory|Total Memory|Memory Speed|Mem| \
        #                           Memory Voltage|ECC|CAP|Scrub|Mode|Policy|Revision|Channel' >> mrc.txt"
        mrc_contents = cimc_debug_handle.execute_cmd_serial(cmd3)
        # open the file mrc.txt for reading
        cmd = "cat mrc.txt"
        file_contents = cimc_debug_handle.execute_cmd_serial(cmd)
        file_contents = re.sub(
            r'\[.*?\$', "", file_contents, flags=re.IGNORECASE)
        # delete the mrc.txt file form the CIMC debug shell
        cmd = "rm -rf mrc.txt"
        delete_file = cimc_debug_handle.execute_cmd_serial(cmd)
        cimc_debug_handle.disconnect()
        # save the output to the file
        # generate the file
        filename = "MRCout_info_before_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            file_contents, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def usb_info_capture(self,  testbed_name):
        '''
        Collects the CPU info capture after HUU update
        '''
        # Connect host to get the output
        cmd = "lsusb"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # if truue generate the file
        filename = "usb_info_before_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def com_port_info_capture(self,  testbed_name):
        '''
        Collects the CPU info capture after HUU update
        '''
        # Connect host to get the output
        cmd = "dmesg | grep serial"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        var = re.findall(r'(serial+\d+:.*)?\(', output)
        output = "\n".join(var)
        # if truue generate the file
        filename = "com_port_info_before_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)


class SystemInventoryCompareSTD(aetest.Testcase):
    '''
    This class captures the Systen details after the firmware update and compares with already collect STD inventry file
    '''
    logger.info("Start of the class compare")

    @aetest.test
    def cpu_info_compare(self,  testbed_name):
        '''
        Compares the CPU info STD info
        '''
        # Connect host to get the output
        cmd = "cat /proc/cpuinfo | grep -E 'processor|model|core|flag'"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # if true generate the file
        filename_latest = "CPU_info_latest_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # check with the file std id avialbale
        test_dir = testbed_name + "_std_1"
        file_name_std = "CPU_info_std_" + testbed_name
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
                    "Testcase failed :  difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed :  difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def mem_info_compare(self, cimc_util_obj, testbed_name, config):
        '''
        Compares the memory info STD info
        '''
        # Connect host to get the output
        cmd = "cat /proc/meminfo | grep -E 'MemTotal'"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        ###
        # convert Kb to GB approximatly GB
        match = re.search("MemTotal:\s+([^\r\n]+)", output).group(1)
        total_memory_size = match[:5]
        file_content = "MemTotal: " + total_memory_size + " Mb"
        # if true generate the file
        filename_latest = "Mem_info_latest_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            file_content, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # check with the file std id avialbale
        test_dir = testbed_name + "_std_1"
        file_name_std = "Mem_info_std_" + testbed_name
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
                    "Testcase failed :  difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed :  difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def dmidecode_info_compare(self,  testbed_name):
        '''
        Compares the DMidecode info STD info
        '''
        # Connect host to get the output
        cmd = "dmidecode -q"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        ###
        # DMIDdecode
        # if true generate the file
        filename_latest = "Dmidecode_info_latest_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # check with the file std id avialbale
        test_dir = testbed_name + "_std_1"
        file_name_std = "Dmidecode_info_std_" + testbed_name
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
                    "Testcase failed :  difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed :  difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def lspci_dev_info_compare(self,  testbed_name):
        '''
        Compares the LSPCI dev info STD info
        '''
        # Connect host to get the output
        cmd = "lspci -mn"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        ###
        # DMIDdecode
        # if true generate the file
        filename_latest = "Lspci_dev_info_latest_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # check with the file std id avialbale
        test_dir = testbed_name + "_std_1"
        file_name_std = "Lspci_dev_info_std_" + testbed_name
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
                    "Testcase failed :  difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed :  difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def lspci_complete_info_compare(self,  testbed_name):
        '''
        Compares the LSPCI Complete info STD info
        '''
        # Connect host to get the output
        cmd = "lspci -vvvvvvvxxbDkq"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        ###
        # DMIDdecode
        # if true generate the file
        filename_latest = "Lspci_full_info_latest_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # check with the file std id avialbale
        test_dir = testbed_name + "_std_1"
        file_name_std = "Lspci_full_info_std_" + testbed_name
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
                    "Testcase failed :  difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed :  difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def mac_info_compare(self,  testbed_name):
        '''
        Compares the MAC info STD info
        '''
        # Connect host to get the output
        cmd = "ifconfig | grep -E 'HWaddr'"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        ###
        # DMIDdecode
        # if true generate the file
        filename_latest = "MAC_info_latest_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # check with the file std id avialbale
        test_dir = testbed_name + "_std_1"
        file_name_std = "MAC_info_std_" + testbed_name
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
                    "Testcase failed :  difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed :  difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def boot_order_compare(self, cimc_util_obj, testbed_name):
        '''
        Compares the Boot order info STD info
        '''
        # connect to CIMC
        # CIMC connect handle is already availabke in the common setup
        # execute cmd
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        cimc_cli_handle = cimc_util_obj.handle
        output_1 = cimc_cli_handle.execute_cmd_list(
            'top', 'scope bios', 'show actual', 'show actual-boot-order detail', wait_time=20)
        logger.info(str(output_1))
        # parse the output
        lines = output_1.split("\n")
        file_contents = "Boot device : \n\r"
        for line in lines:
            line = line.strip()
            logger.info("Line ...." + str(line))
            match_string = "DeviceName:\s+([^\n\r]+)"
            match_value = re.search(match_string, line)
            if match_value is not None:
                logger.info("Match value...." + match_value.group(1))
                boot_dev_name = match_value.group(1)
                file_contents = file_contents + boot_dev_name + "\n\r"
        # save the output to the file
        filename = "Bootrder_info_latest_" + testbed_name
        file_path_to_save = std_dir + testbed_name + "_1"
        file_creation_status = system_capture_object.generate_file_from_output(
            file_contents, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # check with the file std id avialbale
        filename_latest = filename
        test_dir = testbed_name + "_std_1"
        file_name_std = "Bootorder_info_std_" + testbed_name
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
                    "Testcase failed :  difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed :  difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def bios_token_compare(self, cimc_util_obj, testbed_name):
        '''
        Compares the BIOS token info STD info
        '''
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        cimc_cli_handle = cimc_util_obj.handle

        # out of scope main
        output1 = cimc_cli_handle.execute_cmd_list(
            'top', 'scope bios', 'scope main', 'show detail')
        output1 = output1.split("---")
        output2 = cimc_cli_handle.execute_cmd_list(
            'top', 'scope bios', 'scope server-management', 'show detail')
        output2 = output2.split("---")
        output3 = cimc_cli_handle.execute_cmd_list(
            'top', 'scope bios', 'scope advanced', 'show detail')
        output3 = output3.split("---")
        file_contents = output1[1] + "\n\r" + output2[1] + "\n\r" + output3[1]
        logger.info(str(file_contents))
        # generate the file
        filename = "BIOS_Tokens_latest_std_" + testbed_name
        file_path_to_save = std_dir + testbed_name + "_1"
        file_creation_status = system_capture_object.generate_file_from_output(
            file_contents, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # check with the file std id avialbale
        filename_latest = filename
        test_dir = testbed_name + "_std_1"
        file_name_std = "BIOS_Tokens_info_std_" + testbed_name
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
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def e820_info_compare(self,  testbed_name):
        '''
        Compares the E820 info STD info
        '''
        # Connect host to get the output
        cmd = "dmesg | grep -E 'e820|E820'"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        output = re.sub(
            r'\[.*?\]', "", output, flags=re.IGNORECASE)    
        # if true generate the file
        filename_latest = "E820_info_latest_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # check with the file std id avialbale
        test_dir = testbed_name + "_std_1"
        file_name_std = "E820_info_std_" + testbed_name
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
                    "Testcase failed :  difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed :  difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def cimc_inv_compare(self, cimc_util_obj, testbed_name):
        '''
        Compares the CIMC info info STD info
        '''
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        cimc_cli_handle = cimc_util_obj.handle
        # out of scope main
        file_contents = cimc_cli_handle.execute_cmd_list(
            'top', 'scope chassis', 'inventory-all')
        logger.info(str(file_contents))
        # generate the file
        filename = "CIMC_inv_latest_std_" + testbed_name
        file_path_to_save = std_dir + testbed_name + "_1"
        file_creation_status = system_capture_object.generate_file_from_output(
            file_contents, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # check with the file std id avialbale
        filename_latest = filename
        test_dir = testbed_name + "_std_1"
        file_name_std = "CIMC_inv_info_std_" + testbed_name
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
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def cimc_mac_address_compare(self, cimc_util_obj, testbed_name):
        '''
        Compares the CIMC address info STD info
        '''
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        cimc_cli_handle = cimc_util_obj.handle
        # out of scope main
        logger.info("Inside the CIMCMAccaddressCapture")
        # generate thw slot ID list
        file_contents = "MAC List :"
        slot_id = system_capture_object.get_slot_cimc()
        logger.info(slot_id)
        # append the MAC list to the filecontents
        for slot in slot_id:
            output = system_capture_object.get_mac_cimc(slot)
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
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def usb_info_compare(self, cimc_util_obj, testbed_name, config):
        '''
        Compares the CPU info STD info
        '''
        # Connect host to get the output
        cmd = "lsusb"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # if true generate the file
        filename_latest = "usb_info_latest_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # check with the file std id avialbale
        test_dir = testbed_name + "_std_1"
        file_name_std = "usb_info_std_" + testbed_name
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
                    "Testcase failed :  difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed :  difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def com_port_info_compare(self,  testbed_name):
        '''
        Compares the CPU info STD info
        '''
        # Connect host to get the output
        cmd = "dmesg | grep serial"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        var = re.findall(r'(serial+\d+:.*)?\(', output)
        output = "\n".join(var)
        # if true generate the file
        filename_latest = "com_port_info_latest_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # check with the file std id avialbale
        test_dir = testbed_name + "_std_1"
        file_name_std = "com_port_info_std_" + testbed_name
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
                    "Testcase failed :  difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed :  difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)


class SystemInvCompareAfterUpgarde(aetest.Testcase):
    '''
        the calss comapres the info after the upgfade
    '''

    logger.info("Start of the Comapre After Firmware Upgarde")

    @aetest.test
    def cpu_info_compare_reboot(self,  testbed_name):
        '''
        Compares the CPU  info STD info
        '''
        # Connect host to get the output
        cmd = "cat /proc/cpuinfo | grep -E 'processor|model|core|flag'"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # if truue generate the file
        filename_latest = "CPU_info_after_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # check with the file std id avialbale
        file_name_std = "CPU_info_before_update_" + testbed_name
        file_path_std = file_name_std
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
                    "Testcase failed :  difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed :  difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def mem_info_compare(self,  testbed_name):
        '''
        Compares the MEM info info STD info
        '''
        # Connect host to get the output
        cmd = "cat /proc/meminfo | grep -E 'MemTotal'"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        ###
        # convert Kb to GB approximatly GB
        match = re.search("MemTotal:\s+([^\r\n]+)", output).group(1)
        total_memory_size = match[:5]
        file_content = "MemTotal: " + total_memory_size + " Mb"
        # if true generate the file
        filename_latest = "Mem_info_after_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            file_content, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # check with the file std id avialbale
        file_name_std = "Mem_info_before_update_" + testbed_name
        file_path_std = file_name_std
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
                    "Testcase failed :  difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed :  difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def dmidecode_info_compare(self,  testbed_name):
        '''
        Compares the Dmidecode info
        '''
        # Connect host to get the output
        cmd = "dmidecode -q"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        ###
        # DMIDdecode
        # if true generate the file
        filename_latest = "Dmidecode_info_after_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # check with the file std id avialbale
        file_name_std = "Dmidecode_info_before_update_" + testbed_name
        file_path_std = file_name_std
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
                    "Testcase failed :  difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed :  difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def lspci_dev_info_compare(self,  testbed_name):
        '''
        Compares the LSPCI Dev info
        '''
        # Connect host to get the output
        cmd = "lspci -mn"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        ###
        # DMIDdecode
        # if true generate the file
        filename_latest = "Lspci_dev_info_after_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # check with the file std id avialbale
        file_name_std = "Lspci_dev_info_before_update_" + testbed_name
        file_path_std = file_name_std
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
                    "Testcase failed :  difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed :  difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def lspci_complete_info_compare(self,  testbed_name):
        '''
        Compares the LSPCI complete info STD info
        '''
        # Connect host to get the output
        cmd = "lspci -vvvvvvvxxbDkq | grep -E 'Device|controller|bridge|periphera|DevSta|LnkCap|LnkCtl|LnkSta|IRQ|Bus|slot'"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd,cmd_wait_time=120)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        ###
        # DMIDdecode
        # if true generate the file
        filename_latest = "Lspci_full_info_after_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # check with the file std id avialbale
        file_name_std = "Lspci_full_info_before_update_" + testbed_name
        file_path_std = file_name_std
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
                    "Testcase failed :  difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed :  difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def mac_info_compare(self,  testbed_name):
        '''
        Compares the MAC address info STD info
        '''
        # Connect host to get the output
        cmd = "ifconfig | grep -E 'HWaddr'"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        ###
        # DMIDdecode
        # if true generate the file
        filename_latest = "MAC_info_after_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # check with the file std id avialbale
        file_name_std = "MAC_info_before_update_" + testbed_name
        file_path_std = file_name_std
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
                    "Testcase failed :  difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed :  difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def boot_order_compare(self, cimc_util_obj, testbed_name):
        '''
        Compares the boot order info info STD info
        '''
        # connect to CIMC
        # CIMC connect handle is already availabke in the common setup
        # execute cmd
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        cimc_cli_handle = cimc_util_obj.handle
        output = cimc_cli_handle.execute_cmd_list(
            'top', 'scope bios', 'show actual', 'show actual-boot-order detail', wait_time=20)
        logger.info(str(output))
        # parse the output
        lines = output.split("\n")
        file_contents = "Boot device : \n\r"
        for line in lines:
            line = line.strip()
            logger.info("Line ...." + str(line))
            match_string = "DeviceName:\s+([^\n\r]+)"
            match_value = re.search(match_string, line)
            if match_value is not None:
                logger.info("Match value...." + match_value.group(1))
                boot_dev_name = match_value.group(1)
                file_contents = file_contents + boot_dev_name + "\n\r"
        # save the output to the file
        filename_latest = "Bootrder_info_after_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            file_contents, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # check with the file std id avialbale
        file_name_std = "Bootorder_info_before_update_" + testbed_name
        file_path_std = file_name_std
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
                    "Testcase failed :  difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed :  difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def e820_info_compare_reboot(self,  testbed_name):
        '''
        Compares the E820 info STD info
        '''
        # Connect host to get the output
        cmd = "dmesg | grep -E 'e820|E820'"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        output = re.sub(
            r'\[.*?\]', "", output, flags=re.IGNORECASE)    
        # if truue generate the file
        filename_latest = "E820_info_after_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # check with the file std id avialbale
        file_name_std = "E820_info_before_update_" + testbed_name
        file_path_std = file_name_std
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
                    "Testcase failed :  difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed :  difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def bios_token_compare(self, cimc_util_obj, testbed_name):
        '''
        Compares the BIOS tokens info STD info
        '''
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        cimc_cli_handle = cimc_util_obj.handle
        # out of scope main
        output1 = cimc_cli_handle.execute_cmd_list(
            'top', 'scope bios', 'scope main', 'show detail')
        output1 = output1.split("---")
        output2 = cimc_cli_handle.execute_cmd_list(
            'top', 'scope bios', 'scope server-management', 'show detail')
        output2 = output2.split("---")
        output3 = cimc_cli_handle.execute_cmd_list(
            'top', 'scope bios', 'scope advanced', 'show detail')
        output3 = output3.split("---")
        file_contents = output1[1] + "\n\r" + output2[1] + "\n\r" + output3[1]
        logger.info(str(file_contents))
        # generate the file
        filename_latest = "BIOS_Tokens_after_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            file_contents, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # check with the file std id avialbale
        file_name_std = "BIOS_Tokens_info_before_update_" + testbed_name
        file_path_std = file_name_std
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
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def cimc_inv_compare(self, cimc_util_obj, testbed_name, config):
        '''
        Compares the CIMC Inv compare info STD info
        '''
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        cimc_cli_handle = cimc_util_obj.handle
        # out of scope main
        file_contents = cimc_cli_handle.execute_cmd_list(
            'top', 'scope chassis', 'inventory-all')
        logger.info(str(file_contents))
        # generate the file
        filename_latest = "CIMC_inv_after_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            file_contents, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # check with the file std id avialbale
        file_name_std = "CIMC_inv_info_before_update_" + testbed_name
        file_path_std = file_name_std
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
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def mrc_out_compare(self, cimc_util_obj, testbed_name, config):
        '''
        Compares the MRC out comapre info STD info
        '''
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        # connect to CMIC debug shell
        cimc_debug_handle = cimc_util_obj.telnet_handle
        cimc_debug_handle.connect_to_mgmnt()
        # change the prompt to linux shell
        prompt = 'linuxMode'
        cimc_debug_handle.set_bmc_serial_mode(prompt)
        # execute the command for grep the MRCOUt
        platform_type = config.mgmtdetail.platform_series
        if platform_type == 'M5':
            cmd1 = "cd /mnt/jffs2/BIOS/bt"
            cmd2 = "cat MrcOut"
            cmd3 = "cat MrcOut | grep -E 'Socket|Effective Memory|Total Memory|Memory Speed|Mem| \
                                   Memory Voltage|ECC|CAP|Scrub|Mode|Policy|Revision|Channel' >> mrc.txt"
        else:
            cmd1 = "cd /var/nuova/BIOS"
            cmd2 = "cat MrcOut.txt"
            cmd3 = "cat MrcOut.txt | grep -E 'Socket|Effective Memory|Total Memory|Memory Speed|Mem| \
                                   Memory Voltage|ECC|CAP|Scrub|Mode|Policy|Revision|Channel' >> mrc.txt"

        #cmd = "cd /var/nuova/BIOS"
        output = cimc_debug_handle.execute_cmd_serial(cmd1)
        cmd = "ls"
        output = cimc_debug_handle.execute_cmd_serial(cmd)
        #cmd = "cat MrcOut.txt"
        output = cimc_debug_handle.execute_cmd_serial(cmd2)
        logger.info(" ####### Out of the MRC ############")
        logger.info(output)
        #cmd = "cat MrcOut.txt | grep -E 'Socket|Effective Memory|Total Memory|Memory Speed|Mem| \
        #                           Memory Voltage|ECC|CAP|Scrub|Mode|Policy|Revision|Channel' >> mrc.txt"
        mrc_contents = cimc_debug_handle.execute_cmd_serial(cmd3)
        # open the file mrc.txt for reading
        cmd = "cat mrc.txt"
        file_contents = cimc_debug_handle.execute_cmd_serial(cmd)
        file_contents = re.sub(
            r'\[.*?\$', "", file_contents, flags=re.IGNORECASE)
        # delete the mrc.txt file form the CIMC debug shell
        cmd = "rm -rf mrc.txt"
        delete_file = cimc_debug_handle.execute_cmd_serial(cmd)
        cimc_debug_handle.disconnect()
        # save the output to the file
        # generate the file
        filename_latest = "MRCout_info_after_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            file_contents, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # check with the file std id avialbale
        file_name_std = "MRCout_info_before_update_" + testbed_name
        file_path_std = file_name_std
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
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def usb_info_compare_reboot(self,  testbed_name):
        '''
        Compares the CPU  info STD info
        '''
        # Connect host to get the output
        cmd = "lsusb"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # if truue generate the file
        filename_latest = "usb_info_after_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # check with the file std id avialbale
        file_name_std = "usb_info_before_update_" + testbed_name
        file_path_std = file_name_std
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
                    "Testcase failed :  difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed :  difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def com_port_info_compare_reboot(self,  testbed_name):
        '''
        Compares the CPU  info STD info
        '''
        # Connect host to get the output
        cmd = "dmesg | grep serial"
        # create an object for System capture library
        #system_capture_object = SystemDetailsCapture(cimc_util_obj, config)
        output = system_capture_object.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        var = re.findall(r'(serial+\d+:.*)?\(', output)
        output = "\n".join(var)
        # if truue generate the file
        filename_latest = "com_port_info_after_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        # check with the file std id avialbale
        file_name_std = "com_port_info_before_update_" + testbed_name
        file_path_std = file_name_std
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
                    "Testcase failed :  difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed :  difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)


class CommonCleanUp(Cleanup):
    '''
        Compares the Comom clean
    '''

    @aetest.subsection
    def cleanup(self, mgmt_handle):
        super(CommonCleanUp, self).clean_everything(mgmt_handle)
