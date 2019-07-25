from _ast import IsNot
from _collections import defaultdict
import logging

from ats import aetest
from ats import easypy
from cimc_utils import *
from common_test import Setup, Cleanup
from config_parser import ConfigParser
from linux_utils import LinuxUtils
from smbios_lib import SmbiosLib
from telnet_utils import TelnetUtil
from boot_order import BootOrder


# Get your logger for your script
logger = logging.getLogger(__name__)

key_map = {'sn': 'serialnumber', 'uuid': 'uuid', 'asset-tag': 'assettag', 'productid': 'productname', 'bios-version': 'version',
           'version': 'version', 'core-count': 'corecount', 'current-speed': 'currentspeed', 'thread-count': 'threadcount', 'signature': 'signature'}
smbios_dict = {
    'dmidecode0': [['top', 'scope bios', 'show detail'], ['vendor'], ['bios-version'], 'dmidecode -t 0'],
    'dmidecode1': [['top', 'scope chassis', 'show detail'], ['manufacturer', 'version', 'ProductName', 'SerialNumber', 'UUID'], ['sn'], 'dmidecode -t 1'],
    'dmidecode2': [['top', 'scope chassis', 'show detail'], ['manufacturer', 'productName', 'serialnumber', 'type', 'assettag', 'version'], ['productid'], 'dmidecode -t 2'],
    'dmidecode3': [['top', 'scope chassis', 'show detail'], ['manufacturer', 'boot-upstate', 'SerialNumber', 'type', 'assettag', 'powersupplystate', 'thermalstate', 'height'], ['sn'], 'dmidecode -t 3'],
    'dmidecode16': [[], ['location', 'user', 'errorcorrectiontype', 'maximuncapacity', 'errorinfocapacity', 'numberofdevices'], [], 'dmidecode -t 16'],
    'dmidecode19': [[], ['startingadress', 'physicalarrayhandle', 'paritionwidth'], [], 'dmidecode -t 19'],
    'dmidecode32': [[], ['status'], [], 'dmidecode -t 32'],

    #'dmidecode4': [['top', 'scope chassis', 'show cpu detail'], ['socketdesignation', 'family', 'signature'], ['version', 'core-count', 'current-speed', 'thread-count', 'signature'], 'dmidecode -t 4', 'Processor Information'],
    'dmidecode4': [['top', 'scope chassis', 'show cpu detail'], ['socketdesignation', 'family'], [], 'dmidecode -t 4', 'Processor Information'],
    'dmidecode7': [[], ['configuration,errorcorrectiontype,associativity'], [], 'dmidecode -t 7', 'Socket Designation'],


    'smbiosview0': [[], ['structuretype', 'manufacturer', 'vendor', 'version', 'interanchor', 'SMBIOSBCDRevision'], [], 'smbiosview -t 0'],
    'smbiosview1': [[], ['structuretype', 'manufacturer', 'productname', 'version'], [], 'smbiosview -t 1'],
    'smbiosview2': [[], ['structuretype', 'manufacturer', 'productname', 'baseboardboardtype'], [], 'smbiosview -t 2'],
    'smbiosview3': [[], ['manufacturer', 'type', 'enclosureheight', 'systemenclosureorchassistypes'], [], 'smbiosview -t 3'],
    'smbiosview16': [[], ['structuretype', 'physicalmemoryarrayLocation', 'physicalmemoryarrayuse', 'physicalmemoryarrayerrorcorrectiontypes', 'maximumcapacity', 'MemoryErrorInformationHandle', 'numberofmemorydevices'], [], 'smbiosview -t 16'],
    'smbiosview19': [[], ['structuretype', 'startingaddress', 'endingaddress'], [], 'smbiosview -t 19'],
    'smbiosview32': [[], ['structuretype', 'systembootstatus'], [], 'smbiosview -t 32'],
    'smbiosview4': [[], ['structuretype', 'socket', 'processormanufacture', 'processorversion', 'maxspeed', 'currentspeed', 'processorupgrade', 'corecount', 'enabledcorecount', 'threadcount'], [], 'smbiosview -t 4'],
    'smbiosview7': [[], ['structuretype', 'socketdesignation', 'cacheerrorcorrectingtype', 'cachesystemcachetype', 'cacheassociativity'], [], 'smbiosview -t 7'],
    'smbiosview9': [[], ['structuretype', 'systembootstatus'], [], 'smbiosview -t 9'],


}

classparam = {}

class CommonSetup(Setup):

    @aetest.subsection
    def connect(self, testscript, testbed_name):
        super(CommonSetup, self).connect(testscript, testbed_name)

    @aetest.subsection
    def inital_setup(self,cimc_util_obj, config):
        '''
        Initial Setups
        '''
        global classparam
        classparam['boot_order_object'] = BootOrder(cimc_util_obj, config)
        classparam['cimc_util_obj'] = cimc_util_obj
        classparam['smbios_obj'] = SmbiosLib()
        bios_obj = cimc_util_obj.bios_util_obj

        # Disable SOL
        if bios_obj.enable_disable_sol(value='no') is False:
            log.warning('Failed to set console redirect default values')
        if bios_obj.console_redirect_defaults() is False:
            log.warning('Failed to set console redirect default values')


class SMBIOS(aetest.Testcase):

    #### EFI shell based testcases
    @aetest.test.loop(uids= ['smbiosview_0','smbiosview_1','smbiosview_2','smbiosview_3','smbiosview_16','smbiosview_19','smbiosview_32'],parameter=['smbiosview0','smbiosview1','smbiosview2','smbiosview3','smbiosview16','smbiosview19','smbiosview32'])
    def EFI_test (self,cimc_util_obj,testbed_name,parameter,config):
        logger.info("Inside the  EFI Shell SMBIOS testcase")
        host_serial_handle =cimc_util_obj.telnet_handle
        efi_connect_status = classparam['boot_order_object'].boot_to_efi_shell()
        logger.info("AFTER THE METHOD CONNECTING TO efI")
        #### loading the SMBIOS platform dictory file
        config_parser = ConfigParser(testbed_name)
        mgmt_detail_obj = config.mgmtdetail
        platform = mgmt_detail_obj.platform
        config_file = 'SMBIOS_DATA' + "_" + platform
        file_data = config_parser.load_config(config_file)
        result = 0 
        if efi_connect_status is not False:
            logger.info("Successfully Booted to EFI shell")
            cmd = smbios_dict[parameter][3]
            out=host_serial_handle.execute_cmd_serial_host(cmd)
            host_serial_handle.disconnect()
            logger.info("EFI shell out ......."+out)
            
            ## call the fucntion to generate to generare dict out of EFI
            smbios_dict_efi=classparam['smbios_obj'].create_dict_from_output(out) 
            if smbios_dict_efi == 'False':
                logger.error ("Failed creating Directory out of the EFI shell")
                result = 1 

            ### generate Dict out of the config file 
            smbiostabletype = parameter
            smbios_dict_file=classparam['smbios_obj'].create_dict_from_file(file_data,smbiostabletype)
            if smbios_dict_file == 'False':
                logger.error("Failed creating Directory out of the Config file")
                result = 1
                
            ### 1 verifying the between the EFI and SMBIOS DATA FILE
            check_point_1_status = 0 
            testcase_status = classparam['smbios_obj'].verify_keys(smbios_dict_efi, smbios_dict_file) 
            if check_point_1_status == 1:
                result = 1
                logger.error("Parameter name mismatch between the SMBIOS EFI output and CONFIG File")
            else :
                logger.info("All the parameter names for the SMBIOS are populated in the output") 
            
             #### 2 . No Zero validation    
            for key in smbios_dict_efi:
                if smbios_dict_efi[key] != " ":
                    print (smbios_dict_efi[key])
                    logger.info("value is a Non Zero")
                else:
                    logger.error("value is empty for "+key)
                    result = 1     
            
             #### 3 . list of values verification 
            print ("List of Value Verification starts Here")
            #verify_list = ['structuretype', 'manufacturer','productname','version']
            verify_list=smbios_dict[parameter][1]
            check_point_3_status = 0
            check_point_3_status=classparam['smbios_obj'].verify_keys_values(smbios_dict_efi, smbios_dict_file, verify_list)
            if check_point_3_status == 1 :
                result =1
                logger.error("value mismatch between the SMBIOS EFI output and CONFIG file details ")                        
        else :
           logger.error("Unable to boot to EFI ")
           result = 1

        if result == 1:
            self.failed("Testcase failed")



    # Dmidecode based testcases

    @aetest.test.loop(uids=['demidecode_0', 'demidecode_1', 'dmidecode_2', 'dmidecode_3', 'demidecode_16', 'dmidecode_19', 'dmidecode_32'], parameter=['dmidecode0', 'dmidecode1', 'dmidecode2', 'dmidecode3', 'dmidecode16', 'dmidecode19', 'dmidecode32'])
    def test(self, mgmt_handle, telnet_handle,testbed_name, parameter, config):
        # host_os_ip = "10.225.78.28"
        # host_os_user_name="root"
        # host_os_password="topspin"
        result = 0
        config_parser = ConfigParser(testbed_name)
        mgmt_detail_obj = config.mgmtdetail
        platform = mgmt_detail_obj.platform
        config_file = 'SMBIOS_DATA' + "_" + platform
        file_data = config_parser.load_config(config_file)
        table_found = 1
        OS_handle = classparam['cimc_util_obj'].host_handle
        #get host IP details
        host_os_ip = classparam['smbios_obj'].get_host_mgmt_ip(config)
       # OS_handle=LinuxUtils(ip=host_os_ip,username=host_os_user_name,password=host_os_password)
        # ## Pinging os the OS IP
        Host_ping_status = classparam['cimc_util_obj'].verify_host_up(
            hostname=host_os_ip, wait_for_ping_fail=False, wait_time=600)
        if Host_ping_status == True:
            print("Host OS is pinging  ...")
            OS_handle.connect()
        else:
            output = classparam['boot_order_object'].set_boot_order_HDD()
            if output == True:
                Host_ping_status = classparam['cimc_util_obj'].verify_host_up(
                    hostname=host_os_ip, wait_for_ping_fail=False, wait_time=600)
                if Host_ping_status == True:
                    print("Host OS is pinging  ...")
                    OS_handle.connect()
                else:
                    logger.error(
                        " ERROR :Host OS is not pinging ,after setting the boot order to HDD and retrying ...")
                    self.failed(
                        " Testcase failed .... since Unabke to boot to OS")
            else:
                logger.error(
                    " ERROR :Host OS is not pinging , failed to Set the boot order to HDD")
                self.failed(" Testcase failed .... since Unabke to boot to OS")
            # break
        time.sleep(5)
        # cmd="dmidecode -t 1"
        cmd = smbios_dict[parameter][3]
        out = OS_handle.execute_cmd(cmd)
        # # call the fucntion to generate form linux
        smbios_dict_linux = classparam['smbios_obj'].create_dict_from_output(out)
        if smbios_dict_linux == 'False':
            logger.error("Failed creating Directory out of the EFI shell")
            result = 1
        # ## generate Dict out of the config file
        smbiostabletype = parameter
        dmi_dict_file = classparam['smbios_obj'].create_dict_from_file(
            file_data, smbiostabletype)
        if classparam['smbios_obj'].is_empty(dmi_dict_file) == False:
            # ## 1 verifying the between the Dmidecode and SMBIOS DATA FILE
            check_point_1_status = 0
            testcase_status = classparam['smbios_obj'].verify_keys(
                smbios_dict_linux, dmi_dict_file)
            if check_point_1_status == 1:
                result = 1
                logger.error(
                    "Parameter name mismatch between the SMBIOS EFI output and CONFIG File")
            else:
                logger.info(
                    "All the parameter names for the SMBIOS are populated in the output")
            # 2 . No Zero validation
            for key in smbios_dict_linux:
                if smbios_dict_linux[key] != " ":
                    print(smbios_dict_linux[key])
                    logger.info("value for key " + key + "is  Non Zero ")
                else:
                    logger.error("value is empty for key " + key)
                    result = 1
            # 3 . list of values verification
            logger.info(
                ".......List of Value Verification starts Here........")
            # verify_list = ['manufacturer','version','ProductName','SerialNumber','UUID']
            verify_list = smbios_dict[parameter][1]
            check_point_3_status = 0
            check_point_3_status = classparam['smbios_obj'].verify_keys_values(
                smbios_dict_linux, dmi_dict_file, verify_list)
            if check_point_3_status == 1:
                result = 1
                logger.error(
                    "value mismatch between the SMBIOS EFI output and CONFIG file details ")
            # 4. verifying dynamic values comparising
            if classparam['smbios_obj'].is_empty(smbios_dict[parameter][2]) == False:
                # start  genreating dynamic dict form CIMC
                cimc_CLI_handle = classparam['cimc_util_obj'].handle
                # cimc_CLI_handle.connect()
                for cmd in smbios_dict[parameter][0]:
                    CIMC_output = cimc_CLI_handle.execute_cmd(cmd)
                # #closing CIMC session before disconnectng
                cimc_CLI_handle.execute_cmd_list('top', 'exit')
                # cimc_CLI_handle.disconnect()
                dynamic_list = smbios_dict[parameter][2]
                dynamic_value_dic = classparam['smbios_obj'].creating_dynamic_dict_from_cimc(
                    CIMC_output, dynamic_list, key_map)
                if classparam['smbios_obj'].is_empty(dynamic_value_dic) == True:
                    logger.error(
                        "Error in generating dynamic value dict form CIMC")
                    result = 1
                # comapre the values form dynamic dict and dmidecode dict
                check_point_4_status = 0
                check_point_4_status = classparam['smbios_obj'].verify_keys_values(
                    smbios_dict_linux, dynamic_value_dic)
                if check_point_4_status == 1:
                    result = 1
                    logger.error(
                        "value mismatch between the SMBIOS Linux output and Dynamic value output ")
        else:
            self.failed(
                "Unable to find SMBIOS table in the data file . Please check the data file for SMBIOS table" + smbiostabletype)
            result = 1

        if result == 1:
            # self.failed ( " Testcase failed")
            self.failed("Testcase failed")

    # Dmidecode 4 and 7 testcases

    #@aetest.test.loop(uids=['demidecode_4', 'dmidecode_7'], parameter=['dmidecode4', 'dmidecode7'])
    def test3(self, mgmt_handle, telnet_handle,testbed_name, parameter, config):
        # ## OS IP
        result = 0
        config_parser = ConfigParser(testbed_name)
        mgmt_detail_obj = config.mgmtdetail
        platform = mgmt_detail_obj.platform
        config_file = 'SMBIOS_DATA' + "_" + platform
        file_data = config_parser.load_config(config_file)
        table_found = 1
        OS_handle = classparam['cimc_util_obj'].host_handle
        # ## geting host IP
        host_os_ip = classparam['smbios_obj'].get_host_mgmt_ip(config)

        Host_ping_status = classparam['cimc_util_obj'].verify_host_up(
            hostname=host_os_ip, wait_for_ping_fail=False, wait_time=600)
        if Host_ping_status == True:
            print("Host OS is pinging  ...")
            OS_handle.connect()
        else:
            output = classparam['boot_order_object'].set_boot_order_HDD()
            if output == True:
                Host_ping_status = classparam['cimc_util_obj'].verify_host_up(
                    hostname=host_os_ip, wait_for_ping_fail=False, wait_time=600)
                if Host_ping_status == True:
                    logger.info("Host OS is pinging  ...")
                    OS_handle.connect()
                else:
                    logger.error(
                        "ERROR :Host OS is not pinging ,after setting the boot order to HDD and retrying ...")
                    self.failed(
                        "Testcase failed .... since Unabke to boot to OS")
            else:
                logger.error(
                    " ERROR :Host OS is not pinging , failed to Set the boot order to HDD")
                self.failed(" Testcase failed .... since Unabke to boot to OS")

        time.sleep(10)
        # execute the command Dmiecode
        cmd = smbios_dict[parameter][3]
        output = OS_handle.execute_cmd(cmd)
        logger.info(output)

        # ## parse the output into dictionary
        parse_string = smbios_dict[parameter][4]
        output = output.split(parse_string)
        logger.info(output)

        index_value = 1
        smbios_dict_block = defaultdict(dict)
        for block in output[1:]:
            smbios_dict_linux = {}
            logger.info("..... Splited  blocks .....")
            logger.info(block)
            # smbios_dict_linux = self.create_dict_form_output(block)
            smbios_dict_linux = classparam['smbios_obj'].create_dict_from_output(block)
            smbios_dict_block[index_value] = smbios_dict_linux
            index_value = index_value + 1
        # create dictionary form file
        dmi_dict_file = {}
        dmi_dict_table_no = parameter
        dmi_dict_file = classparam['smbios_obj'].create_dict_from_file(
            file_data, dmi_dict_table_no)
        for key in smbios_dict_block:
            logger.info(
                "key = " + str(key) + "value =" + str(smbios_dict_block[key]))
            smbios_dict_linux_modinfo = smbios_dict_block[key]
            # 1. check the non Zero value
            for keys1 in smbios_dict_linux_modinfo:
                logger.info(
                    "keys1 =" + str(keys1) + "value ..." + str(smbios_dict_linux_modinfo[keys1]))
                if smbios_dict_linux_modinfo[keys1] != " ":
                    print(smbios_dict_linux_modinfo[keys1])
                    logger.info(
                        "value for key " + str(keys1) + "is  Non Zero " + "in the block " + str(key))
                else:
                    logger.error(
                        "value is empty for key " + str(keys1) + "in the block " + str(key))
                    result = 1
            # ## 2 verifying the between the Dmidecode and SMBIOS DATA FILE
            check_point_1_status = 0
            testcase_status = classparam['smbios_obj'].verify_keys(
                smbios_dict_linux_modinfo, dmi_dict_file)
            if check_point_1_status == 1:
                result = 1
                logger.error(
                    "Parameter name mismatch between the SMBIOS EFI output and CONFIG File" + "in the block " + str(key))
            else:
                logger.info(
                    "All the parameter names for the SMBIOS are populated in the output" + "in the block " + str(key))
            # 3 . list of values verification
            logger.info(
                ".......List of Value Verification starts Here........")
            # verify_list = ['manufacturer','version','ProductName','SerialNumber','UUID']
            verify_list = smbios_dict[parameter][1]
            check_point_3_status = 0
            check_point_3_status = classparam['smbios_obj'].verify_keys_values(
                smbios_dict_linux_modinfo, dmi_dict_file, verify_list)
            if check_point_3_status == 1:
                result = 1
                logger.error(
                    "value mismatch between the SMBIOS EFI output and CONFIG file details ""in the block " + str(key))
            # Dynamic value verification
            # 4. verifying dynamic values comparising
            if classparam['smbios_obj'].is_empty(smbios_dict[parameter][2]) == False:
                # start  genreating dynamic dict form CIMC
                cimc_CLI_handle = classparam['cimc_util_obj'].handle
                # cimc_CLI_handle.connect()
                for cmd in smbios_dict[parameter][0]:
                    CIMC_output = cimc_CLI_handle.execute_cmd(cmd)
                    # #closing CIMC session before disconnectng
                    # cimc_CLI_handle.execute_cmd_list('top','exit')
                    # cimc_CLI_handle.disconnect()
                dynamic_list = smbios_dict[parameter][2]
                dynamic_value_dic = classparam['smbios_obj'].creating_dynamic_dict_from_cimc(
                    CIMC_output, dynamic_list, key_map)
                if classparam['smbios_obj'].is_empty(dynamic_value_dic) == True:
                    logger.error(
                        "Error in generating dynamic value dict form CIMC")
                    result = 1
                # comapre the values form dynamic dict and dmidecode dict
                check_point_4_status = 0
                check_point_4_status = classparam['smbios_obj'].verify_keys_values(
                    smbios_dict_linux, dynamic_value_dic)
                if check_point_4_status == 1:
                    result = 1
                    logger.error(
                        "value mismatch between the SMBIOS Linux output and Dynamic value output ")
            # ## end of inner for loop
        # ## end of outer for loop
        if result == 1:
            self.failed(" Testcase failed ")
        OS_handle.disconnect()

    ###########
    # SMBIOS Type testcase
    ###########
    @aetest.test
    def Dmidecode9(self,testbed_name, config):

        # ## verify OS pinging connect to os
        result = 0

        mgmt_detail_obj = config.mgmtdetail
        platform = mgmt_detail_obj.platform
        config_file = 'SMBIOS_DATA' + "_" + platform
        config_parser = ConfigParser(testbed_name)
        file_data = config_parser.load_config(config_file)

        table_found = 1
        OS_handle = classparam['cimc_util_obj'].host_handle
        host_os_ip = classparam['smbios_obj'].get_host_mgmt_ip(config)
        Host_ping_status = classparam['cimc_util_obj'].verify_host_up(
            hostname=host_os_ip, wait_for_ping_fail=False, wait_time=600)
        if Host_ping_status == True:
            print("Host OS is pinging  ...")
            OS_handle.connect()
        else:
            output = classparam['boot_order_object'].set_boot_order_HDD()
            if output == True:
                Host_ping_status = classparam['cimc_util_obj'].verify_host_up(
                    hostname=host_os_ip, wait_for_ping_fail=False, wait_time=600)
                if Host_ping_status == True:
                    logger.info("Host OS is pinging  ...")
                    OS_handle.connect()
                else:
                    logger.error(
                        "ERROR :Host OS is not pinging ,after setting the boot order to HDD and retrying ...")
                    self.failed(
                        "Testcase failed .... since Unabke to boot to OS")
            else:
                logger.error(
                    " ERROR :Host OS is not pinging , failed to Set the boot order to HDD")
                self.failed(" Testcase failed .... since Unable to boot to OS")

        # ## execute the command dmidecode -t 9
        cmd = "dmidecode -t 9"
        output = OS_handle.execute_cmd(cmd)
        logger.info(output)

        # ## parse the output into dictionary
        parse_string = "System Slot Information"
        output = output.split(parse_string)
        logger.info(output)

        # ## Two diminesinal Dict form the output
        index_value = 1
        smbios_dict_slot_details = defaultdict(dict)
        for block in output[1:]:
            regex = 'Designation\s*\:\s+([^\\r\\n]+)'
            key = re.search(regex, block).group(1).replace(
                ":", '').lower().replace(" ", '')
            smbios_dict_slot_details[key] = {}
            regex = 'Type\s*\:\s+([^\r\\n]+)'
            smbios_dict_slot_details[key][
                'type'] = re.search(regex, block).group(1)
            logger.info(key + "...." + smbios_dict_slot_details[key]['type'])

        # Ceate dictory form
        dmi_dict_table_no = "dmidecode9"
        dmidecode_9_slot_list = file_data.config.get(
            dmi_dict_table_no, 'slotlist')
        for key in dmidecode_9_slot_list.split(","):
            if file_data.config.get(key, 'type') == smbios_dict_slot_details[key]['type']:
                logger.info(
                    " Value matched between the Linux and config file ")
            else:
                logger.error("Value mismatch")
                logger.error("dmidecode obtained value ..." +
                             key + ":" + smbios_dict_slot_details[key]['type'])
                logger.error("Config file obtained value ..." +
                             key + ":" + file_data.config.get(key, 'type'))
                self.failed(" Dmidecode and Config file value mimatch")
    

class CommonCleanUp(Cleanup):

    @aetest.subsection
    def cleanup(self, mgmt_handle, config):
        host_os_ip = classparam['smbios_obj'].get_host_mgmt_ip(config)
        output = classparam['boot_order_object'].set_boot_order_HDD()
        if output == True:
            Host_ping_status = classparam['cimc_util_obj'].verify_host_up(
                hostname=host_os_ip, wait_for_ping_fail=False, wait_time=600)
        super(CommonCleanUp, self).clean_everything(mgmt_handle)
