'''
smbios_lib.py


Class contains all vic related procedures
'''

from _ast import IsNot
from _collections import defaultdict
from _collections import defaultdict
import logging
import re
import time

from common_utils import dump_error_in_lib
from config_parser import ConfigParser
from linux_utils import LinuxUtils


logger = logging.getLogger(__name__)


class SmbiosLib(object):

    def create_dict_from_output(self, EFI_output):
        try:
            lines = EFI_output.split("\n")
            generate_dict_efi = {}
            smbios_dict_file = {}
            logger.info("..... Server Obtained EFI SMBIOS values......")
            for line in lines:
                if line.find(':') != -1:
                    key1 = line.split(':')[0].replace(' ', '').strip().lower()
                    value1 = line.split(':')[1].replace(' ', '').strip().lower()
                    logger.info(key1 + "....." + value1)
                    generate_dict_efi[key1] = value1
            return generate_dict_efi
        except:
            dump_error_in_lib()
            return False

    def create_dict_from_file(self, filehandle, tabletype):
        try:
            table_found = 0
            for val in filehandle.config.sections():
                # logger.info ('val....='+val)
                smbiostable = tabletype
                create_dict_form_file = {}
                if smbiostable == val:
                    table_found = 1
                    logger.info("..... CONFIG FILE reference  values......")
                    for val1 in filehandle.config[val]:
                        logger.info(
                            "keys=" + val1 + "...." + "values=" + filehandle.config[val][val1])
                        create_dict_form_file[
                            val1] = filehandle.config[val][val1]
                    return create_dict_form_file

            if table_found == 0:
                logger.error(
                    "Unable to find SMBIOS table in the data file . Please check the data file for SMBIOS table" + smbiostable)
                return False
        except:
            dump_error_in_lib()
            return False

    def verify_keys(self, smbios_dict, config_file_dict):
        smbios_dict_efi = smbios_dict
        smbios_dict_file = config_file_dict
        result = 0
        for key in smbios_dict_file:
            try:
                if key in smbios_dict_efi:
                    logger.info("Found SMBIOS parameter ......" + key)
                else:
                    logger.error(
                        "Unable to find the SMBIOS parameter in the EFI shell output ....." + key)
                    # self.failed('SMBIOS value not found in the the EFI shell...'+key)
                    # logger.error("value obtained form EFI shell.."+smbios_dict_efi[key]+"is not matching value obtained form CONFIG file "+smbios_dict_file[key] )
                    result = 1
            except Exception as inst:
                logger.error("Caught exception while reading the config file")
                logger.error(type(inst))
                logger.error(inst.args)
                logger.error(
                    'SMBIOS value not found in the the EFI shell...' + key)
                result = 1
        return result

    def verify_keys_values(self, smbios_dict, config_file_dict, verify_list=None):
        try:
            smbios_dict_efi = smbios_dict
            smbios_dict_file = config_file_dict
            result = 0
            for key in smbios_dict_file:
                logger.info("key..." + key)
                if verify_list is not None:
                    if key in verify_list:
                        logger.info("key= " + key + "found in the dynamic list")
                        logger.info(
                            "key=....." + key + "..value...=" + smbios_dict_file[key])
                        EFI_shell_value = smbios_dict_efi[
                            key].replace(" ", "").strip().lower()
                        Config_file_value = smbios_dict_file[
                            key].replace(" ", "").strip().lower()
                        out = re.match(
                            Config_file_value, EFI_shell_value, re.IGNORECASE)
                        if out is not None:
                            logger.info(
                                "Server obtained value for" + key + "...=" + smbios_dict_efi[key])
                            logger.info(
                                "SMBIOS CONFIG FILE  obtained value for" + key + "...=" + smbios_dict_file[key])
                            logger.info("Values matched")
                        else:
                            logger.error(
                                "server obtained value for " + key + "...=" + smbios_dict_efi[key])
                            logger.error(
                                " CONFIG FILE  obtained value for " + key + "...=" + smbios_dict_file[key])
                            logger.error(
                                "server obtained value and CONFIG File values mismatch")
                            result = 1
                else:
                    # logger.info("key=....."+key+"..value...="+smbios_dict_file[key])
                    EFI_shell_value = smbios_dict_efi[key].replace(
                        " ", "").strip().lower().replace(')', '').replace('(', '')
                    Config_file_value = smbios_dict_file[key].replace(
                        " ", "").strip().lower().replace(')', '').replace('(', '')
                    out = re.match(
                        Config_file_value, EFI_shell_value, re.IGNORECASE)
                    if out is not None:
                        logger.info(
                            "Server obtained value for" + key + "...=" + EFI_shell_value)
                        logger.info(
                            "SMBIOS CONFIG FILE  obtained value for" + key + "...=" + Config_file_value)
                        logger.info("Values matched")
                    else:
                        logger.error(
                            "server obtained value for " + key + "...=" + EFI_shell_value)
                        logger.error(
                            " CONFIG FILE  obtained value for " + key + "...=" + Config_file_value)
                        logger.error(
                            "server obtained value and CONFIG File values mismatch")
                        result = 1
            return result
        except:
            dump_error_in_lib()
            return 1

    def creating_dynamic_dict_from_cimc(self, cimc_output, dynamic_list, key_map):
        output = cimc_output
        dynamic_value_dic = {}
        for item in dynamic_list:
            regex = item + "\s*\:\s+([^\r\n]+)"
            item_value = re.search(regex, output).group(1)
            logger.info(
                "CIMC obtained dynamic value for " + item + "=" + item_value)
            dynamic_value_dic[key_map[item]] = item_value
        return dynamic_value_dic

    def is_empty(self, any_structure):
        if not any_structure:
            logger.error('Structure is empty.')
            return True
        else:
            logger.info('Structure is not empty.')
            return False

    def get_host_mgmt_ip(self, config):
        ntw_list = config.host_info[0].nw_intf_list
        logger.info('Management interface is:' + ntw_list[0].is_mgmt_intf)
        for intf in ntw_list:
            if intf.is_mgmt_intf == 'yes':
                logger.info('Host Managment IP is: ' + intf.ip_address)
                host_ip = intf.ip_address
        return host_ip
