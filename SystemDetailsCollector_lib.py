import difflib
import logging
import os
import subprocess
from common_utils import dump_error_in_lib
import re
import stat
from smbios_lib import SmbiosLib
from boot_order import BootOrder
import time


# Get your logger for your script
logger = logging.getLogger(__name__)


class SystemDetailsCapture(object):
    '''
       Class SystemDetails Lib for System Details capture
    '''

    def __init__(self, cimc_util_obj, config):
        self.cimc_util_obj = cimc_util_obj
        self.config = config
        self.boot_order_obj = BootOrder(cimc_util_obj, config)

    def connect_host_execute_command(self, testbed_name, cmd,cmd_wait_time=None):
        '''
        proc to Connect to host and return the output of the executed command
        return - False if failed
        '''
        smbios_obj = SmbiosLib()
        os_handle = self.cimc_util_obj.host_handle
        host_os_ip = smbios_obj.get_host_mgmt_ip(self.config)
        host_ping_status = self.cimc_util_obj.verify_host_up(
            hostname=host_os_ip, wait_for_ping_fail=False, wait_time=600)

        if host_ping_status is True:
            logger.info("Host OS is pinging  ...")
            time.sleep(10)
            os_handle.connect()
        else:
            output = self.boot_order_obj.set_boot_order_HDD()
            if output == True:
                host_ping_status = self.cimc_util_obj.verify_host_up(
                    hostname=host_os_ip, wait_for_ping_fail=False, wait_time=600)
                if host_ping_status is True:
                    logger.info("Host OS is pinging  ...")
                    time.sleep(10)
                    os_handle.connect()
                else:
                    logger.error("ERROR :Host OS is not pinging \
                                ,after setting the boot order to HDD and retrying ...")
                    logger.error(
                        "Testcase failed .... since Unabke to boot to OS")
                    return False
            else:
                logger.error(
                    " ERROR :Host OS is not pinging , failed to Set the boot order to HDD")
                return False
        # ## Execute the command for and get the output
        if host_ping_status is True:
            if cmd_wait_time == None :
                cmd_wait_time = 4   
            output = os_handle.execute_cmd(cmd,buffer_size=150000, wait_time=cmd_wait_time)
            logger.info(output)
            os_handle.disconnect()
            return output

    def generate_file_from_output(self, output, file_name):
        '''
        generate the file based on the content and save the file to path
        return - True if successfull
        return - False if unsuccessfull
        '''
        logger.info(output)
        # ##convert Output to byts
        try:
            output = str(output).replace('\b', '')
            # ## open a file
            file_handle = open(file_name, "w")
            # ## dump the command output to the file
            file_handle.write(output)
            # ## close the file
            file_handle.close()
            logger.info("File is generated successfully  : " + file_name)
            # ## the save in the location /data/software/capture system details
            return True
        except:
            dump_error_in_lib()
            logger.error("Error in generating the file" + file_name)
            return False

    def copy_file_to_share(self, file_name, path_to_copy):
        '''
        copies the file to share path
        returns - True if successfull
        returns - False if unscessfull
        '''
        try:
            if not os.path.exists(path_to_copy):
                logger.info(
                    path_to_copy + " Directory doesnt exists .Hence creating directory")
                os.makedirs(path_to_copy)
                os.chmod(path_to_copy, stat.S_IRWXO)
            copy_command = "cp -rf " + file_name + " " + path_to_copy
            copy_output = subprocess.check_output(copy_command, shell=True,
                                                  stderr=subprocess.STDOUT)
            logger.info(str(copy_output))
            file_path = path_to_copy + file_name
            if os.path.exists(file_path):
                logger.info(
                    "Successfull copied the file to the path :" + file_path)
                return True
            else:
                logger.error(
                    "Error in copying the file: " + file_name + "to directory:" + path_to_copy)
                return False
        except:
            dump_error_in_lib()
            logger.error("Expection obtained in Copying the file" +
                         file_name + "to directory:" + path_to_copy)
            return False

    def file_compare(self, file_path_1, file_path_2):
        '''
        Compares two files and returns True if there is no difference
        '''
        try:
            file1 = open(file_path_1, "r")
            file2 = open(file_path_2, 'r')
            file_diff = difflib.context_diff(
                file1.readlines(), file2.readlines())
            delta = ''.join(file_diff)
            if not delta:
                logger.info(
                    " There is not differece between the STD and Lstest data" + str(delta))
                return True
            else:
                logger.error(
                    " There is difference between STD and latest data" + str(delta))
                return False
        except:
            dump_error_in_lib()
            logger.info(
                " Exception obtained while comparing the STD and laetst config files")
            return False

    def get_slot_cimc(self):

        try:
            mgmt_handle = self.cimc_util_obj.handle

            output = mgmt_handle.execute_cmd_list(
                'top', 'scope chassis', 'show network-adapter detail')
            slot_id = []
            logger.info("Output......" + output)
            for block in output.split("---")[1:]:
                slot = re.search(r'Slot:*\s+([^\r\n]+)', block).group(1)
                slot_id.append(slot)
                interface = re.search(
                    r'NoOfInterfaces:*\s+([^\r\n]+)', block).group(1)
                logger.info(str(interface))
                logger.info("SLot info ...." + slot)
            return slot_id
        except:
            dump_error_in_lib()
            logger.error(" Error in getting SLOT ID")
            return False

    def get_mac_cimc(self, slot_id):

        try:
            mgmt_handle = self.cimc_util_obj.handle
            for val in slot_id:
                output = mgmt_handle.execute_cmd_list(
                    'scope network-adapter ' + str(val), 'show mac-list detail')
                mac_address = []
                for block in output.split("---")[1:]:
                    mac = re.search(
                        r'MacAddress:*\s+([^\r\n]+)', block).group(1)
                    mac_address.append(mac)
                    logger.info("cimc mac info...." + str(mac_address))
                return mac_address
        except:
            dump_error_in_lib()
            logger.error(
                " Error in getting  MAC address for the SLOT ID" + slot_id)
            return False
