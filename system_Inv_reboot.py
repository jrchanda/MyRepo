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

system_captue_obj = ''

class CommonSetup(Setup):
    '''
        #Common setup section
    '''

    @aetest.subsection
    def connect(self, testscript, testbed_name, iteration):
        aetest.loop.mark(SystemReboot, number_of_iteration=iteration)
        super(CommonSetup, self).connect(testscript, testbed_name)
        
    @aetest.subsection
    def inital_setup(self,cimc_util_obj,config):
        global system_capture_obj
        system_capture_obj = SystemDetailsCapture(cimc_util_obj, config)    
        
        


class SystemInventoryCapture(aetest.Testcase):
    '''
    Systen Inv section
    '''
    logger.info("Start of the class Inv Capture")
                 

    @aetest.test
    def cpu_info_capture(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to capture CPU info before reboot
        '''
        # Connect host to get the output
        cmd = "cat /proc/cpuinfo | grep -E 'processor|model|core|flag'"
        # create an object for System capture library
        output = system_capture_obj.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # ## if truue generate the file
        filename = "CPU_info_std_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def mem_info_capture(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to capture Memory Info info before reboot
        '''
        # Connect host to get the output
        cmd = "cat /proc/meminfo | grep -E 'MemTotal'"
        # create an object for System capture library

        output = system_capture_obj.connect_host_execute_command(
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
        file_creation_status = system_capture_obj.generate_file_from_output(
            file_content, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def dmidecode_info_capture(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to capture Dmidecode info before reboot
        '''
        # Connect host to get the output
        cmd = "dmidecode -q"
        # create an object for System capture library
        output = system_capture_obj.connect_host_execute_command(
            cimc_util_obj, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # # DMIDecode convserion
        filename = "Dmidecode_info_std_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def lspci_dev_info_capture(self, cimc_util_obj, testbed_name, config):
        '''
            #Testcase to capture LSPCI info 
        '''
        # Connect host to get the output
        cmd = "lspci -mn"
        # create an object for System capture library
        output = system_capture_obj.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # # DMIDecode convserion
        filename = "Lspci_dev_info_std_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def lspci_info_capture(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to capture LSPCI
        '''
        # Connect host to get the output
        cmd = "lspci -vvvvvvvxxbDkq | grep -E 'Device|controller|bridge|periphera|DevSta|LnkCap|LnkCtl|LnkSta|IRQ|Bus|slot'"
        # create an object for System capture library
        output = system_capture_obj.connect_host_execute_command(
            testbed_name, cmd,cmd_wait_time=120)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # # DMIDecode convserion
        filename = "Lspci_full_info_std_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def mac_addr_info_capture(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to MAC address capture info before reboot
        '''
        # Connect host to get the output
        cmd = "ifconfig | grep -E 'HWaddr'"
        # create an object for System capture library
        output = system_capture_obj.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # # DMIDecode convserion
        filename = "MAC_info_std_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def e820_info_capture(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to E820 info before reboot
        '''
        # Connect host to get the output
        cmd = "dmesg | grep -E 'e820|E820'"
        # create an object for System capture library
        output = system_capture_obj.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        ### remove the lines starting with [
        output = re.sub(
            r'\[.*?\]', "", output, flags=re.IGNORECASE)    
        # ## if truue generate the file
        filename = "E820_info_std_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def boot_order_capture(elf, cimc_util_obj, testbed_name, config):
        '''
        Testcase to Boot order info before reboot
        '''
        # ## connect to CIMC
        # CIMC connect handle is already availabke in the common setup
        # ## execute cmd
        # create an object for System capture library
        cimc_cli_handle = cimc_util_obj.handle
        # cmd_list = ['top','scope bios','show actual','show actual-boot-order detail']
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
        # ## save the output to the file
        filename = "Bootorder_info_std_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            file_contents, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def bios_token_capture(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to BIOS tokens info before reboot
        '''
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
        file_creation_status = system_capture_obj.generate_file_from_output(
            file_contents, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def cimc_inv_capture(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to capture CIMC HW inv info before reboot
        '''
        cimc_cli_handle = cimc_util_obj.handle
        # ## out of scope main
        file_contents = cimc_cli_handle.execute_cmd_list(
            'top', 'scope chassis', 'inventory-all')
        logger.info(str(file_contents))
        # ## generate the file
        filename = "CIMC_inv_info_std_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            file_contents, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def mrc_out_capture(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to MRC out info before reboot
        '''
        # ## connect to CMIC debug shell
        cimc_debug_handle = cimc_util_obj.telnet_handle
        cimc_debug_handle.connect_to_mgmnt()
        # ## change the prompt to linux shell
        prompt = 'linuxMode'
        cimc_debug_handle.set_bmc_serial_mode(prompt)
        # ## execute the command for grep the MRCOUt
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
        # delete the mrc.txt file form the CIMC debug shell
        cmd = "rm -rf mrc.txt"
        delete_file = cimc_debug_handle.execute_cmd_serial(cmd)
        # Subtitude the last line with space
        file_contents = re.sub(
            r'\[.*?\$', "", file_contents, flags=re.IGNORECASE)
        cimc_debug_handle.disconnect()
        # ## save the output to the file
        # ## generate the file
        filename = "MRCout_info_std_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            file_contents, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def usb_info_capture(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to capture CPU info before reboot
        '''
        # Connect host to get the output
        cmd = "lsusb"
        # create an object for System capture library
        output = system_capture_obj.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # ## if truue generate the file
        filename = "usb_info_std_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)

    @aetest.test
    def com_port_info_capture(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to capture CPU info before reboot
        '''
        # Connect host to get the output
        cmd = "dmesg | grep serial"
        # create an object for System capture library
        output = system_capture_obj.connect_host_execute_command(
            testbed_name, cmd)
        var = re.findall(r'(serial+\d+:.*)?\(', output)
        output = "\n".join(var)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # ## if truue generate the file
        filename = "com_port_info_std_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            output, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)


class SystemReboot(aetest.Testcase):

    logger.info("Start of the server reboot test")

    @aetest.setup
    def section_setup(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to section setup
        '''
        # ## Reboot the Host before the start of the iteration
        cmd = "reboot"
        output = system_capture_obj.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command :" + cmd + " For rebooting the Host")
        # ## verify the host is up after the reboot
        smbios_obj = SmbiosLib()
        host_os_ip = smbios_obj.get_host_mgmt_ip(config)
        Host_ping_status_after_reboot = cimc_util_obj.verify_host_up(
            hostname=host_os_ip, wait_for_ping_fail=True, wait_time=720)
        if Host_ping_status_after_reboot is True:
            logger.info(
                "Host has successfull booted after the reboot.. Starting to continue with other test")
        else:
            self.failed(
                "Host is not pinging after the reboot command . Waited time = 6 mins")

    @aetest.test
    def cpu_info_compare_reboot(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to Cpu Info after renoot
        '''
        # Connect host to get the output
        cmd = "cat /proc/cpuinfo | grep -E 'processor|model|core|flag'"
        # create an object for System capture libr
        output = system_capture_obj.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # ## if truue generate the file
        filename_latest = "CPU_info_latest_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # ## check with the file std id avialbale
        file_name_std = "CPU_info_std_" + testbed_name
        file_path_std = file_name_std
        logger.info("....." + str(os.path.exists(file_path_std)))
        if os.path.exists(file_path_std):
            logger.info(file_name_std + "is available for comparison")
            file_diff_status = system_capture_obj.file_compare(
                file_path_std, filename_latest)
            if file_diff_status is True:
                self.passed("Testcase Passed : no difference between " +
                            file_name_std + " and " + filename_latest)
            else:
                logger.error(
                    "Testcase failed : Difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed : Difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def mem_info_compare(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to capture Mem info before reboot
        '''
        # Connect host to get the output
        cmd = "cat /proc/meminfo | grep -E 'MemTotal'"
        # create an object for System capture library
        output = system_capture_obj.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # ##
        # # convert Kb to GB approximatly GB
        match = re.search("MemTotal:\s+([^\r\n]+)", output).group(1)
        total_memory_size = match[:5]
        file_content = "MemTotal: " + total_memory_size + " Mb"
        # ## if true generate the file
        filename_latest = "Mem_info_latest_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            file_content, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # ## check with the file std id avialbale
        file_name_std = "Mem_info_std_" + testbed_name
        file_path_std = file_name_std
        logger.info("....." + str(os.path.exists(file_path_std)))
        if os.path.exists(file_path_std):
            logger.info(file_name_std + "is available for comparison")
            file_diff_status = system_capture_obj.file_compare(
                file_path_std, filename_latest)
            if file_diff_status is True:
                self.passed("Testcase Passed : no difference between " +
                            file_name_std + " and " + filename_latest)
            else:
                logger.error(
                    "Testcase failed : Difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed : Difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def dmidecode_info_compare(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to capture demidecode info before reboot
        '''
        # Connect host to get the output
        cmd = "dmidecode -q"
        # create an object for System capture library
        output = system_capture_obj.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # ##
        # # DMIDdecode
        # ## if true generate the file
        filename_latest = "Dmidecode_info_latest_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # ## check with the file std id avialbale
        file_name_std = "Dmidecode_info_std_" + testbed_name
        file_path_std = file_name_std
        logger.info("....." + str(os.path.exists(file_path_std)))
        if os.path.exists(file_path_std):
            logger.info(file_name_std + "is available for comparison")
            file_diff_status = system_capture_obj.file_compare(
                file_path_std, filename_latest)
            if file_diff_status is True:
                self.passed("Testcase Passed : no difference between " +
                            file_name_std + " and " + filename_latest)
            else:
                logger.error(
                    "Testcase failed : Difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed : Difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def lspci_dev_info_compare(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to capture LSPCI Dev info after reboot
        '''
        # Connect host to get the output
        cmd = "lspci -mn"
        # create an object for System capture library
        output = system_capture_obj.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # ##
        # # DMIDdecode
        # ## if true generate the file
        filename_latest = "Lspci_dev_info_latest_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # ## check with the file std id avialbale
        file_name_std = "Lspci_dev_info_std_" + testbed_name
        file_path_std = file_name_std
        logger.info("....." + str(os.path.exists(file_path_std)))
        if os.path.exists(file_path_std):
            logger.info(file_name_std + "is available for comparison")
            file_diff_status = system_capture_obj.file_compare(
                file_path_std, filename_latest)
            if file_diff_status is True:
                self.passed("Testcase Passed : no difference between " +
                            file_name_std + " and " + filename_latest)
            else:
                logger.error(
                    "Testcase failed : Difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed : Difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def lspci_complete_info_compare(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to capture LSPCI PCI info after reboot
        '''
        # Connect host to get the output
        cmd = "lspci -vvvvvvvxxbDkq | grep -E 'Device|controller|bridge|periphera|DevSta|LnkCap|LnkCtl|LnkSta|IRQ|Bus|slot'"
        # create an object for System capture library
        output = system_capture_obj.connect_host_execute_command(
            testbed_name, cmd,cmd_wait_time=120)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # ##
        # # DMIDdecode
        # ## if true generate the file
        filename_latest = "Lspci_full_info_latest_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # ## check with the file std id avialbale
        file_name_std = "Lspci_full_info_std_" + testbed_name
        file_path_std = file_name_std
        logger.info("....." + str(os.path.exists(file_path_std)))
        if os.path.exists(file_path_std):
            logger.info(file_name_std + "is available for comparison")
            file_diff_status = system_capture_obj.file_compare(
                file_path_std, filename_latest)
            if file_diff_status is True:
                self.passed("Testcase Passed : no difference between " +
                            file_name_std + " and " + filename_latest)
            else:
                logger.error(
                    "Testcase failed : Difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed : Difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def mac_info_compare(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to capture Mac Info Compare
        '''
        # Connect host to get the output
        cmd = "ifconfig | grep -E 'HWaddr'"
        # create an object for System capture library
        output = system_capture_obj.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # ##
        # # DMIDdecode
        # ## if true generate the file
        filename_latest = "MAC_info_latest_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # ## check with the file std id avialbale
        file_name_std = "MAC_info_std_" + testbed_name
        file_path_std = file_name_std
        logger.info("....." + str(os.path.exists(file_path_std)))
        if os.path.exists(file_path_std):
            logger.info(file_name_std + "is available for comparison")
            file_diff_status = system_capture_obj.file_compare(
                file_path_std, filename_latest)
            if file_diff_status is True:
                self.passed("Testcase Passed : no difference between " +
                            file_name_std + " and " + filename_latest)
            else:
                logger.error(
                    "Testcase failed : Difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed : Difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def boot_order_compare(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to  Boot order comapre
        '''
        # ## connect to CIMC
        # CIMC connect handle is already availabke in the common setup
        # ## execute cmd
        # create an object for System capture library
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
        # ## save the output to the file
        filename_latest = "Bootrder_info_latest_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            file_contents, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # ## check with the file std id avialbale
        file_name_std = "Bootorder_info_std_" + testbed_name
        file_path_std = file_name_std
        logger.info("....." + str(os.path.exists(file_path_std)))
        if os.path.exists(file_path_std):
            logger.info(file_name_std + "is available for comparison")
            file_diff_status = system_capture_obj.file_compare(
                file_path_std, filename_latest)
            if file_diff_status is True:
                self.passed("Testcase Passed : no difference between " +
                            file_name_std + " and " + filename_latest)
            else:
                logger.error(
                    "Testcase failed : Difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed : Difference Fbetween " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def e820_info_compare_reboot(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to capture E820 info after reboot
        '''
        # Connect host to get the output
        cmd = "dmesg | grep -E 'e820|E820'"
        # create an object for System capture library
        output = system_capture_obj.connect_host_execute_command(
            testbed_name, cmd)
        
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        output = re.sub(
            r'\[.*?\]', "", output, flags=re.IGNORECASE)    
        # ## if truue generate the file
        filename_latest = "E820_info_latest_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # ## check with the file std id avialbale
        file_name_std = "E820_info_std_" + testbed_name
        file_path_std = file_name_std
        logger.info("....." + str(os.path.exists(file_path_std)))
        if os.path.exists(file_path_std):
            logger.info(file_name_std + "is available for comparison")
            file_diff_status = system_capture_obj.file_compare(
                file_path_std, filename_latest)
            if file_diff_status is True:
                self.passed("Testcase Passed : no difference between " +
                            file_name_std + " and " + filename_latest)
            else:
                logger.error(
                    "Testcase failed : Difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed : Difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def bios_token_compare(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to capture BIOS tokens info after reboot
        '''
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
        filename_latest = "BIOS_Tokens_latest_std_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            file_contents, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # ## check with the file std id avialbale
        file_name_std = "BIOS_Tokens_info_std_" + testbed_name
        file_path_std = file_name_std
        logger.info("....." + str(os.path.exists(file_path_std)))
        if os.path.exists(file_path_std):
            logger.info(file_name_std + "is available for comparison")
            file_diff_status = system_capture_obj.file_compare(
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
        Testcase to capture CIMC Inv info after reboot
        '''
        cimc_cli_handle = cimc_util_obj.handle
        # ## out of scope main
        file_contents = cimc_cli_handle.execute_cmd_list(
            'top', 'scope chassis', 'inventory-all')
        logger.info(str(file_contents))
        # ## generate the file
        filename_latest = "CIMC_inv_latest_std_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            file_contents, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # ## check with the file std id avialbale
        file_name_std = "CIMC_inv_info_std_" + testbed_name
        file_path_std = file_name_std
        logger.info("....." + str(os.path.exists(file_path_std)))
        if os.path.exists(file_path_std):
            logger.info(file_name_std + "is available for comparison")
            file_diff_status = system_capture_obj.file_compare(
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
        Testcase to capture MRC out info after reboot
        '''

        # ## connect to CMIC debug shell
        cimc_debug_handle = cimc_util_obj.telnet_handle
        cimc_debug_handle.connect_to_mgmnt()
        # ## change the prompt to linux shell
        prompt = 'linuxMode'
        cimc_debug_handle.set_bmc_serial_mode(prompt)
        # ## execute the command for grep the MRCOUt
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
        # delete the mrc.txt file form the CIMC debug shell
        cmd = "rm -rf mrc.txt"
        delete_file = cimc_debug_handle.execute_cmd_serial(cmd)
        # Subtitude the last line with space
        file_contents = re.sub(
            r'\[.*?\$', "", file_contents, flags=re.IGNORECASE)
        cimc_debug_handle.disconnect()
        # ## save the output to the file
        # ## generate the file
        filename_latest = "MRCout_info_latest" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            file_contents, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # ## check with the file std id avialbale
        file_name_std = "MRCout_info_std_" + testbed_name
        file_path_std = file_name_std
        logger.info("....." + str(os.path.exists(file_path_std)))
        if os.path.exists(file_path_std):
            logger.info(file_name_std + "is available for comparison")
            file_diff_status = system_capture_obj.file_compare(
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
    def usb_info_compare_reboot(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to Cpu Info after renoot
        '''
        # Connect host to get the output
        cmd = "lsusb"
        # create an object for System capture library
        output = system_capture_obj.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command "+cmd)
        # ## if truue generate the file
        filename_latest = "usb_info_latest_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file "+filename_latest)
        # ## check with the file std id avialbale
        file_name_std = "usb_info_std_" + testbed_name
        file_path_std = file_name_std
        logger.info("....." + str(os.path.exists(file_path_std)))
        if os.path.exists(file_path_std):
            logger.info(file_name_std + "is available for comparison")
            file_diff_status = system_capture_obj.file_compare(
                file_path_std, filename_latest)
            if file_diff_status is True:
                self.passed("Testcase Passed : no difference between " +
                            file_name_std + " and " + filename_latest)
            else:
                logger.error(
                    "Testcase failed : Difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed : Difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)

    @aetest.test
    def com_port_info_compare_reboot(self, cimc_util_obj, testbed_name, config):
        '''
        Testcase to Cpu Info after renoot
        '''
        # Connect host to get the output
        cmd = "dmesg | grep serial"
        # create an object for System capture library
        output = system_capture_obj.connect_host_execute_command(
            testbed_name, cmd)
        if output is False:
            self.failed(
                "Error is Connecting to OS and Executing command" + cmd)
        # ## if truue generate the file
        var = re.findall(r'(serial+\d+:.*)?\(', output)
        output = "\n".join(var)
        filename_latest = "com_port_info_latest_" + testbed_name
        file_creation_status = system_capture_obj.generate_file_from_output(
            output, filename_latest)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename_latest)
        # ## check with the file std id avialbale
        file_name_std = "com_port_info_std_" + testbed_name
        file_path_std = file_name_std
        logger.info("....." + str(os.path.exists(file_path_std)))
        if os.path.exists(file_path_std):
            logger.info(file_name_std + "is available for comparison")
            file_diff_status = system_capture_obj.file_compare(
                file_path_std, filename_latest)
            if file_diff_status is True:
                self.passed("Testcase Passed : no difference between " +
                            file_name_std + " and " + filename_latest)
            else:
                logger.error(
                    "Testcase failed : Difference between " + file_name_std + " and " + filename_latest)
                self.failed("Testcase failed : Difference between " +
                            file_name_std + " and " + filename_latest)
        else:
            self.failed(
                "Testcase failed : STD file is not avaliable for comparision: " + file_name_std)
    

class CommonCleanUp(Cleanup):
    '''
    Clean up section
    '''

    @aetest.subsection
    def cleanup(self, mgmt_handle):
        super(CommonCleanUp, self).clean_everything(mgmt_handle)
