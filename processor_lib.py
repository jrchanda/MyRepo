import logging
import time
import re
from collections import defaultdict
from common_utils import dump_error_in_lib
from config_parser import ConfigParser
from boot_order import BootOrder

logger = logging.getLogger(__name__)

__author__ = 'Suren Kumar Moorthy <suremoor@cisco.com>'
__copyright__ = 'Copyright 2016, Cisco Systems'
__email__ = 'suremoor@cisco.com'
__date__ = 'Nov 8,2016'
__version__ = 1.0

class Processor():
    '''
    Holding processor details
    '''
    def __init__(self, name, manufacturer, family, thread_count, core_count, version,
                 current_speed, signature, cpu_status, model, description, pid):
        self.name = name
        self.manufacturer = manufacturer
        self.family = family
        self.thread_count = thread_count
        self.core_count = core_count
        self.version = version
        self.current_speed = current_speed
        self.signature = signature
        self.model = model
        self.cpu_status = cpu_status
        self.description = description
        self.pid = pid

class ProcessorUtils():
    '''
    Holding collections of object required for processor
    '''
    def __init__(self, obj):
        self.bios_util_obj = obj
        self.handle = obj.handle
        self.boot_order_obj = BootOrder(self.bios_util_obj.cimc_obj)
        self.cpu_details = []
        self.processor_config = self.load_cpu_obj()
        self.msr = {"IntelTurboBoostTech" : "1A0", "EnhancedIntelSpeedStep" : "1A0",
                    "ExecuteDisable":"1A0", "HardwarePrefetch":"1A4",
                    "AdjacentCacheLinePrefetch":"1A4", "DirectCacheAccess":"1F8",
                    "lt_lock_memory":"2E7", "pkg_cst":"E2", "plat_info":"0CE",
                    "power_ctl":"1FC", "dynamic_switch":"1FC", "perf_bias":"1FC",
                    "c1e":"1FC", "ia32_energy":"1B0", "Hwpm":"1AA",
                    "cpu_cstate":"E2", 'IA32_Energy_Performance_BIAS':'1B0'}

    def is_msr_bitSet(self, operand, mask_string, flag, bit_position):
        '''
        Bit Manipulator
        Procedure to masks the bits of the msr value per core to get
        the value of the required bit
        Parameter:
        param: operant - Corevalue from EFI
               mask_string - Mask value
               flag - "and" or "or"
               bit_position - bit position to check
        Return:
            Bit value: Success
            False : Failure

        Author: Suren kumar Moorthy
        '''
        try:
            per_core_value = int("0x" + operand, 16)
            mask_value = int("0x" + mask_string, 16)
            if flag == "and":
                res = per_core_value & mask_value
                if res > 0:
                    bit_array = list("{0:b}".format(res))
                    bit_array.reverse()
                    return bit_array[int(bit_position)]
                else:
                    return res
            elif flag == "or":
                return per_core_value | mask_value
            else:
                return False
        except:
            dump_error_in_lib()
            return False

    def get_cpu_info(self):
        '''
        Get Cpu info from CimcUtils
        Procedure loads the cpu info in processor object

        Return:
            Object populated with processor details : SUCCESS
            False : FAILURE

        Authhor : Suren Kumar Moorthy
        '''
        try:

            self.handle.execute_cmd_list("top", "scope chassis")
            out = self.handle.execute_cmd("show cpu detail")
            token_list = ["name", "manufacturer", "family", "thread-count", 'core-count',
                          "version", "current-speed", "signature", 'cpu-status']
            main_param_list = []
            out_list = out.split("---")
            for out_bloc in out_list[1:]:
                param_list = []
                for token in token_list:
                    regex = re.escape(token) + r'\s*\:\s+([^\r\n]+)'
                    value = re.search(regex, out_bloc).group(1)
                    param_list.append(value)
                    if token == 'version':                        
                        model_regex = r'(?:(?:Xeon\(R\)\s*CPU\s+([a-zA-Z0-9\s\-]+)\s+\@)|(?:Xeon\(R\)\s*([a-zA-Z0-9\s\-]+)\s+CPU))'
                        model_reg_out = re.search(model_regex, value)
                        model = str(model_reg_out.group(2)) if model_reg_out.group(1) is None else str(model_reg_out.group(1))                        
                        print('=========*****========****====')
                        print(model)
                        print('=========*****========****====')
                        rep1 = re.compile(r'\s$')
                        model = rep1.sub('', model)
                        rep2 = re.compile(r'\s+')
                        model = rep2.sub('-', model)
                param_list.append(model)
                main_param_list.append(param_list)
            self.handle.execute_cmd_list("top", "scope chassis")
            pid_out = self.handle.execute_cmd("show cpu-pid detail", wait_time=20)
            token_list_pid = ["Description", "PID"]
            pid_out_list = pid_out.split("---")
            i = 0
            for pid_out_bloc in pid_out_list[1:]:
                for token_pid in token_list_pid:
                    regex_pid = re.escape(token_pid) + r'\s*\:\s+([^\r\n]+)'
                    value_pid = re.search(regex_pid, pid_out_bloc).group(1)
                    main_param_list[i].append(value_pid)
                self.cpu_details.append(Processor(main_param_list[i][0], main_param_list[i][1],
                                                  main_param_list[i][2], main_param_list[i][3],
                                                  main_param_list[i][4], main_param_list[i][5],
                                                  main_param_list[i][6], main_param_list[i][7],
                                                  main_param_list[i][8], main_param_list[i][9],
                                                  main_param_list[i][10], main_param_list[i][11]))
                i += 1
            return self.cpu_details
        except:
            dump_error_in_lib()
            return False
    def get_cpu_info_host(self, host_handle, token=None):
        '''
            Collect proccesor information like threads and core from
            host

            Parameter :
                host handle
                token : passing this token will send
                        only the specific tokens(thread,cores)

            Return :
                Returns dictionary with host details
                if token parameter is none else it will
                return the token value : Success
                False : Failure
        '''
        try:
            cpu_info_host = {}
            out = host_handle.execute_cmd("cat /proc/cpuinfo", buffer_size=100000, wait_time=20)
            cpu_info_host['thread'] = len(re.findall(r'processor\s*\:\s*(\d+)', out))
            cpu_info_host['cores'] = re.search(r'cpu\s*cores\s*\:\s*(\d+)', out).group(1)
            if token is None:
                return cpu_info_host
            else:
                return cpu_info_host[token]
        except:
            dump_error_in_lib()
            return False

    def verify_cpu_info(self, cpu_info, token):
        '''
        Verify Cpu info from CimcUtils
        Procedure verify the cpu parameter with
        corresponding processor model in processor config

        Return:
            Object populated with processor details : SUCCESS
            False : FAILURE

        Authhor : Suren Kumar Moorthy
        '''
        try:
            logger.info(getattr(self.processor_config, token))
            if getattr(cpu_info, token) in getattr(self.processor_config, token):
                return True
            else:
                return False

        except:
            dump_error_in_lib()
            return False

    def load_cpu_obj(self):
        '''
            To Load CPU object from config
            Return:
                Object populated with processor details : SUCCESS
                False : FAILURE

            Authhor : Suren Kumar Moorthy
        '''
        try:
            logger.info("Loading CPU object from Config")
            self.handle.execute_cmd_list("top", "scope chassis")
            out = self.handle.execute_cmd("show cpu detail")
            regex = r'(?:(?:Xeon\(R\)\s*CPU\s+([a-zA-Z0-9\s\-]+)(?:\s+)?\@)|(?:Xeon\(R\)\s*([a-zA-Z0-9\s\-]+)\s+CPU))'
            model_reg_out = re.search(regex, out)
            model = str(model_reg_out.group(2)) if model_reg_out.group(1) is None else str(model_reg_out.group(1))
            rep = re.compile(r'\s+$')
            model = rep.sub('', model)
            rep = re.compile(r'\s+')
            model = rep.sub('-', model)
            logger.info('Model selected: ' +model)
            con = ConfigParser()
            proccessor_config = con.load_processor_config(model).proceesor_details
            return proccessor_config
        except:
            dump_error_in_lib()
            return False

    def verify_msr_mode(self, mode, mask_id, bit, verify_bit, out=None):
        '''
            To verify the mode
            Parameter :
                mode : MSR value
                mask_id : Mask id for the msr value
                bit : which bit to check(Ex : 18 th bit)
                verify_bit : Bit to verify (1 or 0)
            Return:
                True or false

            Author : Suren Kumar Moorthy
        '''
        try:
            if out is None:
                host_serial_handle = self.bios_util_obj.cimc_obj.telnet_handle
                efi_out = self.boot_order_obj.boot_to_efi_shell()
                if efi_out is False:
                    return False
                msr_input = 'MSR ' + self.msr[mode]
                out = host_serial_handle.execute_cmd_serial_host(msr_input, wait_time=40)
                logger.info(out)
                host_serial_handle.disconnect()
                time.sleep(60)
            match = re.search(r'\d+\s+\d+\s+\d+\s+([0-9A-Z]{8})\s+([0-9A-Z]{8})', out)
            if match is None:
                logger.error('Unknown MSR Output')
                return False
            core = 1
            fail_flag = 0
            pattern = re.compile(r'\d+\s+\d+\s+\d+\s+([0-9A-Z]{8})\s+([0-9A-Z]{8})')
            for (data1, msr_bit) in re.findall(pattern, out):
                msr_val = data1 + msr_bit
                logger.info("Verify BIT value" + msr_val)
                bit_val = self.is_msr_bitSet(msr_val, mask_id, "and", bit)
                logger.info("Bit Value got is %s" % bit_val)
                logger.info("verify Value got is %s" % verify_bit)
                if int(bit_val) == int(verify_bit):
                    logger.info("Bit value for core " + str(core) + " passed")
                else:
                    fail_flag = 1
                core += 1
            if fail_flag == 1:
                return False
            else:
                return out
        except:
            dump_error_in_lib()
            return False

    def get_smbiosview_processor_param(self, smbios_view):
        '''
            Procedure to get specific tokens form smbios view 4 and 7
            with respective to processor test cases

            Return:
                In case of smbios view 4 returns dictionary of tokens
                In case of smbios 7 returns list of dictionary

            Author : Suren Kumar Moorthy
        '''
        try:
            host_serial_handle = self.bios_util_obj.cimc_obj.telnet_handle
            efi_out = self.boot_order_obj.boot_to_efi_shell()
            smbios_view_token_list = {
                '4' : {'smbios_version' : 'Version', 'name' : 'Socket', \
                       'current_speed' : 'CurrentSpeed', \
                       'processor_upgrade':'Processor Upgrade', \
                       'core_count' : 'CoreCount', \
                       }, \
                 '7' : ['Cache Error Correcting Type', 'Cache System Cache Type']\
            }

            smbios_input = 'smbiosview -t ' + smbios_view
            out = host_serial_handle.execute_cmd_serial_host(smbios_input, wait_time=40)
            logger.info(out)

            if smbios_view == '4':
                smbios_dict = defaultdict(dict)
                for tok in smbios_view_token_list[smbios_view].keys():
                    regex = re.escape(smbios_view_token_list[smbios_view][tok]) + \
                                      r'\s*\:\s+([^\r\n]+)'
                    smbios_dict[tok] = re.search(regex, out, re.IGNORECASE).group(1)
                ret = smbios_dict
            else:
                pattern = re.compile(
                    r'(Type\=7\s*\,[\w\W]*?CPU\s*Internal\s*L3\s*(?:[\w\s]+\s*\:\s*[^\r\n]+\s*)*)')
                cpu = []
                tokens = smbios_view_token_list[smbios_view]
                for core_block in re.findall(pattern, out):
                    smbios_dict = defaultdict(dict)
                    cache_array = re.compile("[=]+?[\n\r]").split(core_block)
                    if len(cache_array) < 4:
                        logger.error("smbios view output format is improper")
                        ret = False
                    else:
                        cache_name = ['l1_cache', 'l1_cache_p', 'l2_cache', 'l3_cache']
                        for cache_key, cache_level in zip(cache_name, cache_array):
                            smbios_dict[cache_key] = defaultdict(dict)
                            for token in tokens:
                                regex = re.escape(token) + r'\s*\:\s*([^\r\n]+)'
                                value = re.search(regex, cache_level).group(1)
                                smbios_dict[cache_key][token] = value
                        cpu.append(smbios_dict)
                ret = cpu

            host_serial_handle.disconnect()
            return ret
        except:
            dump_error_in_lib()
            return False
