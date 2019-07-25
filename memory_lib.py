import logging
import os
import re
import time

from boot_order import BootOrder
from common_utils import dump_error_in_lib
from config_parser import ConfigParser


logger = logging.getLogger(__name__)

__author__ = 'Balamurugan Ramu <balramu@cisco.com>'
__copyright__ = 'Copyright 2016, Cisco Systems'
__email__ = 'balramu@cisco.com'
__date__ = 'Nov 4,2016'
__version__ = 1.0


class Memory():
    '''
     class for storing dimm related values
    '''

    def __init__(self, name, capacity, speed, dimm_type, type_detail, locator, visibility,
                 operability, manufacturer, part_number, serial_number,
                 asset_tag, data_width):
        self.name = name
        self.capacity = capacity
        self.dimm_type = dimm_type
        self.speed = speed.replace(' ', '')
        self.type_detail = type_detail
        self.locator = locator
        self.visibility = visibility
        self.operability = operability
        self.manufacturer = manufacturer
        self.part_number = part_number
        self.serial_number = serial_number
        self.asset_tag = asset_tag
        self.data_width = data_width
        self.capacity_in_gb = 0
        self.rank = ''


class MemoryDPC():
    '''
    class for storing memory DPC and frequency
    '''

    def __init__(self, cpu_model, dpc, rank, size, dimm_frequency,
                 max_cpu_frequency, expected_frequency):
        self.dpc = dpc
        self.rank = rank
        self.size = size
        self.dimm_frequency = dimm_frequency
        self.max_cpu_frequency = max_cpu_frequency
        self.cpu_model = cpu_model
        self.expected_frequency = expected_frequency


class MemoryLib():
    '''
        Library for memory related functions which include configuring memory
        mode , get memory details , get DPC configuration
    '''

    def __init__(self, cimc_utils_obj, host_handle=None):
        self.cimc_utils_obj = cimc_utils_obj
        self.mgmt_handle = cimc_utils_obj.handle
        self.host_handle = host_handle
        self.dimm_list = None
        self.dimm_dpc_list = []
        self.get_memory_details()
        self.bios_utils_obj = cimc_utils_obj.bios_util_obj
        self.load_por()

    def get_ras_mode(self):
        '''
            returns the configured memory mode
        '''
        return self.bios_utils_obj.get_bios_token_value('SelectMemoryRAS').replace(" ","")

    def configure_ras_mode(self, mode='Maximum_Performance'):
        '''
            configure memory mode to one of the below mode based on the
            Parameter (default is Maximum_performance)
            1) Maximum_Performance
            2) Lockstep
            3) Mirroring
        '''

        self.bios_utils_obj.set_bios_token_value('SelectMemoryRAS', mode)
        ras_mode = self.get_ras_mode()
        logger.info('ras mode:' + ras_mode)
        logger.info('expected ras mode:' + mode.replace('_', ''))
        if ras_mode == mode.replace('_', ''):
            return True
        else:
            return False

    def get_memory_details(self):
        '''
        Returns the list of populated dimm's
        '''
        output = self.mgmt_handle.execute_cmd_list('top', 'scope chassis',
                                                   'show dimm detail', buffer_size=500000, wait_time=15)
        name = ''
        capacity = ''
        speed = ''
        dimm_type = ''
        type_detail = ''
        locator = ''
        visibility = ''
        operability = ''
        manufacturer = ''
        part_number = ''
        serial_number = ''
        asset_tag = ''
        data_width = ''
        temp_list = []
        dimm_list = []

        for line in output.splitlines():
            if 'name' in line:
                name = line.split(':')[1]
            elif 'capacity' in line:
                capacity = line.split(':')[1]
            elif 'speed' in line:
                speed = line.split(':')[1]
            elif 'type' in line:
                dimm_type = line.split(':')[1]
            elif 'typedetail' in line:
                type_detail = line.split(':')[1]
            elif 'locator' in line:
                locator = line.split(':')[1]
            elif 'visibility' in line:
                visibility = line.split(':')[1]
            elif 'operability' in line:
                operability = line.split(':')[1]
            elif 'manufacturer' in line:
                manufacturer = line.split(':')[1]
            elif 'partnumber' in line:
                part_number = line.split(':')[1]
            elif 'serialnumber' in line:
                serial_number = line.split(':')[1]
            elif 'assettag' in line:
                asset_tag = line.split(':')[1]
            elif 'datawidth' in line:
                data_width = line.split(':')[1]
                temp_list.append(Memory(name, capacity, speed, dimm_type, type_detail,
                                        locator, visibility, operability, manufacturer, part_number, serial_number, asset_tag, data_width))
        mem_rank_dict = {'1': 'single', '2': 'dual', '4': 'quad'}
        for memory in temp_list:
            if 'Not Installed' not in memory.capacity:
                memory.capacity_in_gb = int(
                    int(memory.capacity.replace(' ', '').replace('MB', '')) / 1024)
                memory.rank = mem_rank_dict[
                    str(int(int(memory.data_width.replace(' ', '').replace('bits', '')) / 64))]
                dimm_list.append(memory)

        logger.info('Memory name and capacity in GB are:')
        logger.info(memory.name)
        logger.info(memory.capacity_in_gb)
        self.dimm_list = dimm_list

        return dimm_list

    def get_memory_summary(self):
        '''
        Returns dimm summary as dictionary.
        '''
        output = self.mgmt_handle.execute_cmd_list('top', 'scope chassis',
                                                   'show dimm-summary detail')
        mem_dict = {}
        for line in output.splitlines():
            if ':' in line:
                mem_dict[
                    line.split(':')[0].replace(
                        ' ',
                        '')] = line.split(':')[1]
        return mem_dict

    def get_dpc(self):
        '''
            returns the dpc configuration of the system
        '''
        dpc = 1
        for dimm in self.dimm_list:
            if '3' in dimm.name:
                dpc = 3
            elif '2' in dimm.name:
                dpc = 2
        return dpc

    def load_por(self, platform='dn'):
        '''
        Loads POR file into an array
        '''
        dimm_csv = open(
            os.environ["GITMAIN"] +
            "/config/" +
            platform +
            '_dimm_frequency.csv')
        for line in dimm_csv:
            dimm_por = line.split(',')
            logger.info(dimm_por[6].rstrip('\n'))
            self.dimm_dpc_list.append(
                MemoryDPC(
                    dimm_por[0],
                    dimm_por[1],
                    dimm_por[2],
                    dimm_por[3],
                    dimm_por[4],
                    dimm_por[5],
                    dimm_por[6].rstrip('\n')))
    # change the method name to get_cpu_memory_supported_freq

    def get_cpu_max_freq(self):
        '''
        returns max cpu dimm supported frequency
        '''
        config = ConfigParser('')
        output = config.load_config('processor_mem_frequency')
        cpu_dict = dict(output.config._sections['cpu_freq'])
        logger.info("CPU dict is")
        logger.info(cpu_dict)
        cli_out = self.mgmt_handle.execute_cmd_list(
            'top',
            'scope chassis',
            'show cpu detail')
        model_regex = r'(?:(?:Xeon\(R\)\s*CPU\s+([a-zA-Z0-9\s\-]+)\s+\@)|(?:Xeon\(R\)\s*([a-zA-Z0-9\s\-]+)\s+CPU))'
        model_reg_out = re.search(model_regex, cli_out)
        logger.info('Regular expr output is: ' + str(model_reg_out))
        cpu_model = (str(model_reg_out.group(2)) if model_reg_out.group(1) is None else str(model_reg_out.group(1))).replace(' ', '').lower()
        return cpu_dict[cpu_model]

    def verify_expected_frequency(self):
        '''
         verifies dimm frequency with POR file.

        '''
        dpc = str(self.get_dpc())
        flag = 0
        mem_sum_dict = self.get_memory_summary()
        frequency = mem_sum_dict['memoryspeed']
        frequency = frequency.replace(' ', '').replace('MHz', '')
        cpu_max_freq = self.get_cpu_max_freq()
        for dimm in self.dimm_list:
            try:
                logger.info('Dimm Check for: ' + str(dimm.__dict__))
            except:
                logger.warning('Ignore warning for Dimm check')
            for por in self.dimm_dpc_list:
                logger.info('POR from dimm_dpc_list for')
                logger.info('por dpc: %s and dpc %s' %(por.dpc, dpc))
                logger.info('POR Rank: %s and dimm rank: %s' %(por.rank, dimm.rank))
                logger.info('por max freq %s and cpu max freq %s' %(por.max_cpu_frequency, cpu_max_freq))
                logger.info('por dim freq %s and dim speed %s' %(por.dimm_frequency, dimm.speed))
                logger.info('por size %s and dim cap in gb %s' %(por.size, dimm.capacity_in_gb))
                if por.dpc == dpc and por.rank == dimm.rank and por.max_cpu_frequency == cpu_max_freq and por.dimm_frequency == dimm.speed and por.size == str(
                        dimm.capacity_in_gb):

                    flag = 1

                    logger.info(
                        'Expected frequency is :' +
                        por.expected_frequency)
                    logger.info('Actual  frequency is :' + frequency)
                    if por.expected_frequency.replace(
                            ' ', '') == frequency.replace(' ', ''):
                        logger.info(
                            'Expected frequency and actual frequency matched')
                    else:
                        logger.error(
                            'Expected frequency is :' +
                            por.expected_frequency)
                        logger.error('Actual  frequency is :' + frequency)
                        return False
                else:
                    logger.warning('configuration not found for dimm' + dimm.name)
                    logger.warning(dimm.__dict__)
                    logger.warning(por.__dict__)
        if flag == 1:
            return True
        else:
            return False

    def calculate_effective_memory(self):
        '''
        Calculates the effective memory based upon the memory mode and dpc configuration
        '''
        mode = self.get_ras_mode()
        logger.info("Mode is"+str(mode))
        size = 0
        for dimm in self.dimm_list:
            size += dimm.capacity_in_gb
        logger.info("Memory size is")
        logger.info(size)
        if mode == 'MaximumPerformance':
            return int(size * 1024)
        elif mode == 'Lockstep':
            return int(size * 1024)
        elif mode == 'Mirroring' or mode == 'MirrorMode1LM':
            return int((size * 1024) / 2)

    def calculate_total_memory(self):
        '''
            Calculates total memory based on the populated DIMM's
        '''
        size = 0
        for dimm in self.dimm_list:
            size += dimm.capacity_in_gb
        return size * 1024

    def verify_memory_config(self):
        '''
          verifies the memory configuration by validating total memory and effective memory
        '''
        mem_summary_dict = self.get_memory_summary()
        total_mem_flag = False
        eff_mem_flag = False
        total_memory = mem_summary_dict['totalmemory'].replace(
            ' ',
            '').replace(
            'MB',
            '')
        eff_memory = mem_summary_dict['effectivememory'].replace(
            ' ',
            '').replace(
            'MB',
            '')
        cal_tot_mem = self.calculate_total_memory()
        cal_eff_mem = self.calculate_effective_memory()
        if int(total_memory) == cal_tot_mem:
            total_mem_flag = True
            logger.info('Actually total memory in MB:' + total_memory)
            logger.info('Calculated total memory in MB:' + str(cal_tot_mem))
        else:
            logger.error('Memory size mismatch in calculation')
            logger.error('Actually total memory in MB:' + total_memory)
            logger.error('Calculated total memory in MB:' + str(cal_tot_mem))

        if int(eff_memory) == cal_eff_mem:
            eff_mem_flag = True
            logger.info('Actually eff memory in MB:' + eff_memory)
            logger.info('Calculated eff memory in MB:' + str(cal_eff_mem))
        else:
            logger.error('Memory size mismatch in calculation')
            logger.error('Actually eff memory in MB:' + eff_memory)
            logger.error('Calculated eff memory in MB:' + str(cal_eff_mem))

        if total_mem_flag and eff_mem_flag:
            return True
        else:
            return False

    def verify_memory_config_in_linux_host(self):
        output = self.host_handle.execute_cmd('cat /proc/meminfo')
        totalmem = 0
        for data in output.splitlines():
            if 'MemTotal:' in data:
                totalmem = int(data.replace('MemTotal:', '').replace('\s', '').replace('kB', '')
                               ) / 1024000
        cimc_eff_mem = self.calculate_effective_memory()
        logger.warning("cimc eff mem is")
        logger.warning(cimc_eff_mem)
        logger.info(
            "memory difference is :" + str(abs(totalmem - (cimc_eff_mem / 1000))))
        if abs(totalmem - (cimc_eff_mem / 1000)) <= 8:
            logger.info('Memory from host is:' + str(totalmem))
            logger.info('Memory from CIMC is:' + str(cimc_eff_mem))
            return True
        else:
            logger.error('Memory from host is:' + str(totalmem))
            logger.error('Memory from CIMC is:' + str(cimc_eff_mem))
            return False

    def verify_memory_config_in_efi_shell(self):
        boot_order_lib = BootOrder(self.cimc_utils_obj)
        memory_cmd = 'Smbiosview -t 203'
        total_mem = ''
        eff_mem = ''
        eff_mem_mode = ''
        mem_vol_efi = 0.0
        boot_result = boot_order_lib.boot_to_efi_shell(post_flag=True)
        logger.info('Boot result data is')
        logger.info(boot_result)
        boot_result = re.sub('[^A-Za-z0-9]+', '', boot_result[1])
        total_mem_post = re.search(r'TotalMemory(.*?)GB', boot_result).group(1)
        logger.info('Total mem post:' + total_mem_post)
        eff_mem_post = re.search(
            r'EffectiveMemory(.*?)GB',
            boot_result).group(1)
        operating_speed_post = re.search(
            r'MemoryOperatingSpeed(.*?)Mhz',
            boot_result).group(1)
        telnet_handle = self.cimc_utils_obj.telnet_handle
        efi_output = telnet_handle.execute_cmd_serial_host(memory_cmd)
        logger.info('EFI shell output is:' + efi_output)
        for data in efi_output.splitlines():
            if 'Total Memory' in data:
                total_mem = data.split(':')[1]
            elif 'Effective Memory' in data:
                eff_mem = data.split(':')[1]
            elif 'Operating Memory Mode' in data:
                eff_mem_mode = data.split(':')[1].replace(" ","")
                if eff_mem_mode == 'Independent':
                    logger.info('Check1: MaximumPerformance')
                    eff_mem_mode = 'MaximumPerformance'
                if eff_mem_mode == 'MirrorMode':
                    logger.info('Check2: MirrorMode1LM')
                    eff_mem_mode = 'MirrorMode1LM'
            elif 'Operating Memory Voltage' in data:
                mem_vol_efi = float(
                    data.split(':')[1].replace(
                        '0V',
                        '').replace(
                        ' ',
                        ''))
        mem_vol_cli = self.get_mem_voltage()
        mem_summary = self.get_memory_summary()
        eff_mem_cli = mem_summary['effectivememory']
        total_mem_cli = mem_summary['totalmemory']
        ras_mode_cli = mem_summary['configuration']
        mem_speed = mem_summary['memoryspeed'].replace(
            ' ',
            '').replace(
            'MHz',
            '')
        logger.info('POST data below:')
        logger.info(total_mem_post)
        logger.info(eff_mem_post)
        logger.info(operating_speed_post)
        logger.info(mem_speed)
        boot_order_lib.change_boot_order(boot_option='hdd')
        telnet_handle.disconnect()
        '''BIOS POST verification
        '''
        total_mem_post = int(total_mem_post) * 1024
        eff_mem_post = int(eff_mem_post) * 1024
        post_result = False

        logger.info('EFI:: total_mem_post: %s and cli: %s' %(total_mem_post, total_mem_cli.replace(' ', '').replace('MB', '')))
        logger.info('EFI:: eff_mem_post: %s and cli: %s' %(eff_mem_post, int(eff_mem_cli.replace(' ', '').replace('MB', ''))))
        logger.info('EFI:: operating speed %s and cli %s' %(operating_speed_post, mem_speed))
        if total_mem_post == int(total_mem_cli.replace(' ', '').replace('MB', '')) and eff_mem_post == int(eff_mem_cli.replace(' ', '').replace
                                                                                                           ('MB', '')) and operating_speed_post == mem_speed:
            logger.info('Memory validation ins post passed')
            post_result = True
        else:
            logger.error('memory validation in post failed')
            logger.error(
                'Total mem in post:' +
                str(total_mem_post) +
                ' and cli:' +
                total_mem_cli.replace(
                    ' ',
                    '').replace(
                    'MB',
                    ''))
            logger.error(
                'eff mem in post:' +
                str(eff_mem_post) +
                ' and cli:' +
                eff_mem_cli.replace(
                    ' ',
                    '').replace(
                    'MB',
                    ''))
            logger.error(
                'mem freq in post:' +
                operating_speed_post +
                ' and cli:' +
                mem_speed)
            post_result = False

        #if total_mem.replace('\s', '') == total_mem_cli.replace('\s', '') and eff_mem.replace('\s', '') == eff_mem_cli.replace(
        #        '\s', '') and eff_mem_mode.replace('\s', '') == ras_mode_cli.replace('\s', '') and mem_vol_cli == mem_vol_efi:
        #    logger.info('mem validation success in efi shell')
        #    return [True, post_result]
        if total_mem.replace('\s', '') == total_mem_cli.replace('\s', '') and eff_mem.replace('\s', '') == eff_mem_cli.replace(
                '\s', '') and eff_mem_mode.replace(' ', '') == ras_mode_cli.replace(' ', ''):
            logger.info('mem validation success in efi shell')
            return [True, post_result]
        else:
            logger.error('memory validation in EFI shell failed')
            logger.error(
                'Total mem in efi:' +
                total_mem +
                ' and cli:' +
                total_mem_cli)
            logger.error(
                'eff mem in efi:' +
                eff_mem +
                ' and cli:' +
                eff_mem_cli)
            logger.error(
                'mem mode in efi:' +
                eff_mem_mode +
                ' and cli:' +
                ras_mode_cli)
            logger.error(
                'memory voltage in efi:' +
                str(mem_vol_efi) +
                'and cli:' +
                str(mem_vol_cli))
            return [False, post_result]

    def get_mem_voltage(self):
        try:
            output = self.cimc_utils_obj.get_sensor_data()
            mem_voltage_dict = {}
            for sensor_data in output:
                print(sensor_data)
                if len(sensor_data) > 0 and 'PVDDQ_' in sensor_data[0]:
                    mem_voltage_dict[sensor_data[0]] = float(sensor_data[2])
                mem_sum = 0.0
            for val in mem_voltage_dict:
                print(val)
                mem_sum += mem_voltage_dict[val]
            mem_voltage = float("{0:.1f}".format(mem_sum / len(mem_voltage_dict)))
            print(mem_voltage)
            logger.info(mem_voltage_dict)
            return mem_voltage
        except:
            logger.error('Unable to read voltage sensor readings')
            dump_error_in_lib()
            return False

    def get_mem_pid(self):
        output = self.mgmt_handle.execute_cmd_list(
            'top',
            'scope chassis',
            'show dimm-pid')
        dimm_list = output.splitlines()
        dimm_dict = {}
        for dimm in dimm_list:
            if dimm != dimm_list[0] and dimm != dimm_list[1] and dimm != dimm_list[
                    2] and dimm != dimm_list[3] and dimm != dimm_list[4]:
                dimm_data = []
                for val in dimm.split(' '):
                    if val != '':
                        dimm_data.append(val)
                if len(dimm_data) > 0 and 'DIMM_' in dimm_data[0]:
                    dimm_dict[dimm_data[0]] = dimm_data[1]

        logger.info(' DIMM Pid list is')
        logger.info(dimm_dict)
        return dimm_dict
