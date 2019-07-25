from collections import defaultdict
import inspect
import logging
import re
import sys
import time

import cimc_utils
import common_utils


logger = logging.getLogger(__name__)

__author__ = 'Suren Kumar Moorthy <suremoor@cisco.com>'
__copyright__ = 'Copyright 2017, Cisco Systems'
__email__ = 'suremoor@cisco.com'
__date__ = 'Feb 15,2017'
__version__ = 1.0


class HostUtils():

    def __init__(self, cimc_util_obj=None, config=None):
        self.config = config
        self.cimc_util_obj = cimc_util_obj
        logger.info("Initialize HostUtil")

    def get_ptu_monitor_out(
            self, host_handle, scope='cpu', cmd="/root/tools/ptumon -t", wait=60):
        '''
            Description:
            To get the average cpu or memory frequency from PTU output

            Parameter : host handle , which frequency(cpu or mem), and hjow much time to monitor

            Returns : List of averages frequency of each cpu
        '''
        try:
            host_handle.execute_cmd('rm -f /root/tools/ptu_mon_file.txt')
            host_handle.execute_cmd(cmd + str(wait) + " >> /root/tools/ptu_mon_file.txt &",
                                    wait_time=20)
            time.sleep(wait)
            out = host_handle.execute_cmd(
                "cat /root/tools/ptu_mon_file.txt",
                wait_time=20)
            freq_list = defaultdict(list)
            if 'cpu' in scope:
                pattern = re.compile(
                    r'(TIME\s*CPU[^\n]*\n(?:(?:(?:[0-9_.]+)|(?:\d{2}\/\d{2}\/\d{2}\s+[0-9:.]+)).*\n)+)')
                data_arr = []
                for cpu_block in re.findall(pattern, out):
                    pattern1 = re.compile(
                        r'(?:(?:\d{2}\/\d{2}\/\d{2}\s+[0-9:.]+)|(?:[0-9_.]+))\s+\S+\s+\S+\s+\S+\s+([0-9.]+)[^\n]*')
                    data_arr.append(re.findall(pattern1, cpu_block))
                [[freq_list[ind].append(round(float(val), 2))
                  for ind, val in enumerate(x)] for x in data_arr]
                freq_avg_list = [round(self.calc_average(value), 2) for key,value in freq_list.items()]
                logger.info('Frequency average list: ' + str(freq_avg_list))
                print(freq_avg_list)
                return freq_avg_list
            else:
                return out
        except:
            curframe = inspect.currentframe()
            calframe = inspect.getouterframes(curframe, 2)
            logger.error(
                "Error occured at the library function call name :" + str(calframe[1][3]))
            logger.error("Error occured is " + sys.exc_info().__str__())
            return False

    def start_ptu_gen(self, host_handle, cmd="./ptu/ptugen -t ", wait=20):
        '''
            Description:
            To Start the ptu stress

            Parameter : host handle , how much time to run the stress

            Returns : returns False in case of any failure else gen out
        '''
        try:
            host_handle.execute_cmd('rm -f /root/tools/ptu_gen_file.txt')
            host_handle.execute_cmd(cmd + str(wait) +
                                    " >> /root/tools/ptu_gen_file.txt &", wait_time=wait)
            return True
        except:
            curframe = inspect.currentframe()
            calframe = inspect.getouterframes(curframe, 2)
            logger.error(
                "Error occured at the library function call name :" + str(calframe[1][3]))
            logger.error("Error occured is " + sys.exc_info().__str__())
            return False

    def calc_average(self, arr=[]):
        tot = 0
        for data in arr:
            tot += data
        return tot / len(arr)

    def get_file_data(self, host_handle, file_path):
        return host_handle.execute_cmd('tail -n5 ' + file_path)

    def check_for_diff(self, file_data_1, file_data_2):
        diff_flag = True
        logger.info("check for diff")
        logger.info(file_data_1)
        logger.info(file_data_2)
        file_data_1 = file_data_1.splitlines()
        file_data_2 = file_data_2.splitlines()
        if len(file_data_1) == len(file_data_2):
            for i in range(len(file_data_1)):
                if file_data_1[i] != file_data_2[i]:
                    logger.error("Difference in content old value is:" + str(file_data_1)
                                 + " and new value is :" + str(file_data_2))
                    diff_flag = False
        else:
            diff_flag = False
            logger.error(
                "Difference in list length and the sequence in old data and new data")
            logger.error(file_data_1)
            logger.error(file_data_2)
        return diff_flag

    def get_host_logs(self, host_handle):
        host_logs_dict = {}
        host_handle.connect()
        host_logs_dict['mcelog'] = self.get_file_data(
            host_handle, "/var/log/mcelog")
        host_handle.disconnect()
        host_handle.connect()
        host_logs_dict['dmesg'] = self.get_file_data(
            host_handle, "/var/log/dmesg")
        host_handle.disconnect()
        host_handle.connect()
        return host_logs_dict

    def check_host_logs_diff(self, log_dict1, log_dict2):
        ret_flag = True
        for keys in log_dict1:
            val1 = log_dict1[keys]
            val2 = log_dict2[keys]
            if not self.check_for_diff(val1, val2):
                logger.error("diff found for key" + str(keys))
                ret_flag = False
        return ret_flag

        '''Procedure to validate dummy files created on respective OS's'''

    def check_file_on_host(self, host_handle, command):
        logger.info(
            'Validate dummy file {} created on booted host OS'.format(command))
        host_ip = self.config.host_info[0].nw_intf_list[0].ip_addr
        res = cimc_utils.CimcUtils.verify_host_up(self, hostname=host_ip, wait_for_ping_fail=False)
        #res = self.cimc_utils_obj.verify_host_up(host_ip, wait_for_ping_fail=False)
        if res is False:
            logger.warning('Failed to ping the host')
        else:
            logger.info("Host IP pinging successfully")
        '''connect to host'''
        logger.info('Sleeping some time for host to restart all its services')
        time.sleep(30)
        if host_handle.connect() is False:
            logger.error('Failed to connect to Host')
            return False
        logger.info('Successfully connected to host')
        out = host_handle.execute_cmd(command)
        if 'No such file or directory' in out or 'File not found' in out or 'command not found' in out:
            logger.error('Failed to verify dummy {} file found on host'.
                         format(command).split()[1])
            return False
        else:
            logger.info('Dummy file found on the remote host' + out)
            return True

    def check_host_up(self, cimc_util_obj, boot_order_obj, config):
        '''
        Procedure to check host is pinging or not. If not, will set the boot order to HDD
        and reboot host and try to ping host again.

        Return values:
            True: if host OS is pinging
            False: if host OS is not pinging
        '''
        host_ip = common_utils.get_host_mgmt_ip(config)
        ping_status = cimc_util_obj.verify_host_up(
            hostname=host_ip, wait_for_ping_fail=False)
        if ping_status is True:
            logger.info('Host OS is UP and is pinging...')
            return True
        else:
            output = boot_order_obj.set_boot_order_HDD()
            if output == True:
                ping_status = cimc_util_obj.verify_host_up(
                    hostname=host_ip, wait_for_ping_fail=False, wait_time=600)
                if ping_status is True:
                    logger.info('Host OS is up and it is pinging...')
                    return True
                else:
                    logger.error('Host OS is not pinging after setting the boot order to HDD')
                    return False

    def get_numa_config_detail(
            self, host_handle, token_status):
        '''
            Description:
            To get the average cpu or memory frequency from PTU output

            Parameter : host handle , which frequency(cpu or mem), and hjow much time to monitor

            Returns : List of averages frequency of each cpu
        '''
        try:
            logger.info('Current token status: ' + token_status)
            host_ip = common_utils.get_host_mgmt_ip(self.config)
            res = cimc_utils.CimcUtils.verify_host_up(self, hostname=host_ip, wait_for_ping_fail=False)
            if res is False:
                logger.warning('Failed to ping the host')
            else:
                logger.info("Host IP pinging successfully")
            '''connect to host'''
            logger.info('Sleeping some time for host to restart all its services')
            time.sleep(30)
            if host_handle.connect() is False:
                logger.error('Failed to connect to Host')
                return False

            cmd = 'grep -i numa /var/log/dmesg'
            host_handle.execute_cmd('rm -f /tmp/numa_cntl.txt')
            host_handle.execute_cmd(cmd + " > /tmp/numa_cntl.txt", wait_time=20)
            time.sleep(5)
            out = host_handle.execute_cmd("cat /tmp/numa_cntl.txt", wait_time=20)
            if token_status == 'Disabled':
                exp_msg = 'No NUMA configuration found'
                match = re.search('No NUMA configuration found', out)
                if match != None:
                    logger.info('Successfully validated NUMA token. As expected, %s, \
                    when NUMA token is Disabled' % (exp_msg))
                    return True
                else:
                    logger.info('Failed to verify NUMA token. Not find %s, \
                    when NUMA token is Disabled' % (exp_msg))
                    return False
            elif token_status == 'Enabled':
                exp_msg = 'Enabling automatic NUMA balancing'
                match = re.search('Enabling automatic NUMA balancing', out)
                if match != None:
                    logger.info('Successfully validated NUMA token. Expected message %s seen, \
                    when NUMA token is Enabled' % (exp_msg))
                    return True
                else:
                    logger.info('Failed to verify NUMA token. Found %s msg , \
                    when NUMA token is Enabled, Not expected' % (exp_msg))
                    return False
        except:
            curframe = inspect.currentframe()
            calframe = inspect.getouterframes(curframe, 2)
            logger.error(
                "Error occured at the library function call name :" + str(calframe[1][3]))
            logger.error("Error occured is " + sys.exc_info().__str__())
            return False

    def connect_host_and_execute_command(self, cmd, boot_order_obj, wait_time=None):
        '''
        proc to Connect to host and return the output of the executed command
        return - False if failed
        '''
        host_handle = self.cimc_util_obj.host_handle
        host_ip = common_utils.get_host_mgmt_ip(self.config)
        host_ping_status = self.cimc_util_obj.verify_host_up(
            hostname=host_ip, wait_for_ping_fail=False, wait_time=600)
        if host_ping_status is True:
            logger.info("Host OS is pinging  ...")
            time.sleep(10)
            host_handle.connect()
        else:
            output = boot_order_obj.set_boot_order_HDD()
            if output == True:
                host_ping_status = self.cimc_util_obj.verify_host_up(
                    hostname=host_ip, wait_for_ping_fail=False, wait_time=600)
                if host_ping_status is True:
                    logger.info("Host OS is pinging  ...")
                    time.sleep(10)
                    host_handle.connect()
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
        # Execute the command for and get the output
        if wait_time == None:
            wait_time = 4
        output = host_handle.execute_cmd(cmd, buffer_size=150000, wait_time=wait_time)
        logger.info(output)
        host_handle.disconnect()
        return output
