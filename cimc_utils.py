'''
Created on Oct 3, 2016

@author: jchanda
'''
from ats import aetest
from ats import easypy

from time import strftime
import logging
import os

import re
import subprocess
import time

from apc_utils import APCUtilClass
from bios_utils import *
from common_utils import dump_error_in_lib
from config_parser import ConfigParser
from linux_utils import LinuxUtils
from vic_lib import VicLib


logger = logging.getLogger(__name__)

__author__ = 'Jagadish Chanda <jchanda@cisco.com>'
__copyright__ = 'Copyright 2016, Cisco Systems'
__email__ = 'jchanda@cisco.com'
__date__ = 'Sept 28, 2016'
__version__ = 1.0

'''
cimc_utils.py

Class to connect to a CIMC and execute various commands

Parameters:
CimcIP  : CIMC IP address or hostname
cimcUser: Username to use for connection
cimcPass: Password for connection

Assumption: SSH service is enabled on remote system

Requirement: pexpect package
'''


class CimcUtils(object):
    hostName = 'None'
    waitForPingFail = 'None'

    def __init__(self, cimc_handle, telnet_handle=None, host_handle=None, config=None, common_config=None):
        self.handle = cimc_handle
        self.telnet_handle = telnet_handle
        self.host_handle = host_handle
        self.bios_util_obj = BiosUtils(self, config, common_config)
        self.config = config

        self.ts_file_path = None
        # self.ts_file_path = 'tmpAutomation-testCase-bmc-2016-12-27_23-11-34.tar.gz'

        '''
        Contructor for the class
        Parameters: Will be taken from global variables
        client : handle for connection
        prompt : Need to update to handle different cases
        '''

    def get_scope_output(self, *scope_list, cmnd='show detail'):
        for scope in scope_list:
            self.handle.execute_cmd(scope)
        if cmnd is None:
            cmnd = 'show detail'
        else:
            cmnd = cmnd
        return self.handle.execute_cmd(cmnd, wait_time=8)

    def power_cycle_host(self, wait_time=60):
        '''
        Procedure to power cycle the host
        Parameter:
            handle : connection handle of cimc
            waitForPingFail : If true, will wait for ping to fail and then back up
                        If False, will return True in case host is responding
            wait_time : Max time attempted to check host's availability
        Return:
            True  : Success
            False : Failure
        '''
        power_off = 0
        power_on = 0
        try:
            power_state = self.get_power_state()
            if power_state == 'off':
                logger.info('Host is already powered off, powering on')
                power_off = 1
                self.set_host_power('on')
            else:
                self.handle.execute_cmd_list(
                    'top', 'scope chassis', 'power cycle', wait_time=6)
                time.sleep(1)
                self.handle.execute_cmd('y')
            # have to add validation
            max_wait_time = time.time() + wait_time  # wait for 60 sec
            while True:
                power_state = self.get_power_state()
                if power_state == 'off':
                    logger.info('Host is powered off')
                    power_off = 1
                elif power_state == 'on':
                    logger.info('Host is powered on')
                    power_on = 1
                if power_on == 1 and power_off == 1:
                    break
                if time.time() > max_wait_time:
                    logger.info('Maximum timeout reached')
                    break
                else:
                    logger.info('Will continue to wait')
                    time.sleep(2)
            if power_off == 1 and power_on == 1:
                logger.info('Successfully power cycled the host')
                return True
            else:
                logger.info('Failed to power cycled the host')
                return False
        except:
            dump_error_in_lib()
            return False

    def get_power_state(self):
        '''
        Procedure to get current power state of host
        Parameter:
            handle : connection handle of cimc
        Return:
            Current power state: Success
            False : Failure
        '''
        logger.info('Getting the current power state of host')
        try:
            self.handle.execute_cmd('top')
            self.handle.execute_cmd('scope chassis')
            out = self.handle.execute_cmd('show detail', wait_time=8)
            time.sleep(3)
            logger.info(out)
            return re.search(r'powerstate:\s+([^\r\n]+)', out).group(1)
        except:
            dump_error_in_lib()
            return False

    def set_host_power(self, power_state):
        '''
        Procedure to power off/on the host
        Parameter:
            power_state: 'on' to power on the host
                        'off' to power off the host
        Return:
            True: Success
            False: Failure
        '''
        try:
            cur_power_state = self.get_power_state()
            if cur_power_state == power_state:
                logger.info(
                    'Host is already in expected powered state: ' + cur_power_state)
                return True
            else:
                out = self.handle.execute_cmd_list('top', 'scope chassis',
                                                   'power ' + power_state, wait_time=6)
                if 'Do you want to continue' in out:
                    self.handle.execute_cmd('y')
                else:
                    logger.error('Failed to power off the host')
                    return False
                cur_power_state = self.get_power_state()
                time.sleep(5)
                if cur_power_state == power_state:
                    logger.info(
                        'Host is successfully set to: ' + cur_power_state)
                else:

                    logger.error(
                        'Failed to power state of host to: ' + power_state)
                    return False
            return True
        except:
            dump_error_in_lib()
            return False

    def reboot_bmc(self, handle):
        '''
        Procedure to get current power state of host
        Parameter:
            handle : connection handle of cimc
        Return:
            True: Success
            False : Failure
        '''
        logger.info('Rebooting CIMC')
        try:
            logger.info(handle.execute_cmd('scope cimc'))
            logger.info(handle.execute_cmd('reboot'))
            logger.info(handle.execute_cmd('y'))
            return True
        except:
            dump_error_in_lib()
            return False

    def reboot_bmc_and_connect(self, config):
        '''
        Procedure to reboot BMC and reconnects the BMC
        Parameter:
            None
        Return:
            True: Success
            False : Failure
        '''
        try:
            logger.info('Rebooting CIMC')
            self.handle.execute_cmd_list('top', 'scope cimc', 'reboot', 'y')
            mgmt_detail_obj = config.mgmtdetail
            bmc_ip = mgmt_detail_obj.bmc_mgmt_ip
            bmc_login = mgmt_detail_obj.bmc_login
            bmc_passwd = mgmt_detail_obj.bmc_password
            logger.info('Successfully rebooted BMC, Wait for BMC to come up')

            res = self.verify_host_up(bmc_ip, wait_time=500)
            if res is not True:
                logger.error('After BMC reboot, failed to ping BMC mgmt IP')
                return False
            else:
                logger.info(
                    'Successfully rebooted BMC, connecting back to BMC')

            self.handle = LinuxUtils(bmc_ip, bmc_login, bmc_passwd)
            self.handle.connect()

            return True
        except:
            dump_error_in_lib()
            return False

    def bmc_factory_reset_and_connect(self):
        '''
        Wrapper procedure to perform BMC factory reset and reconnects to BMC
        Parameter:
            None
        Return:
            True: Success
            False : Failure
        '''
        try:
            logger.info('bmc_factory_reset_and_connect: BMC factory reset and re-connect procedure')
            if self.telnet_handle.bmc_serial_recover_testbed(self.config) is False:
                logger.error('Failed: to perform factory reset and reconnect')
                return False

            mgmt_detail_obj = self.config.mgmtdetail
            bmc_ip = mgmt_detail_obj.bmc_mgmt_ip
            bmc_login = mgmt_detail_obj.bmc_login
            bmc_passwd = mgmt_detail_obj.bmc_password

            logger.info('Wait for BMC to come up')
            res = self.verify_host_up(bmc_ip, wait_time=180)
            if res is not True:
                logger.error('After BMC Factory reset, failed to ping BMC mgmnt IP')
                return False

            # reconnect the BMC after factory reset
            self.handle = LinuxUtils(bmc_ip, bmc_login, bmc_passwd)
            self.handle.connect()
            return True
        except:
            dump_error_in_lib()
            return False

    def ac_cycle_and_reconnect(self, config):
        logger.info('Performing AC cycle')
        apc_obj = config.apcdetails
        apc_ip = apc_obj.apc_ip
        port_list = apc_obj.port_list.split(',')
        model = apc_obj.model

        con = APCUtilClass(apc_ip, "apc1", "nbv12345")
        ret = con.ConnectToAPC()
        if ret != None:
            logger.info('Successfully connected to APC, model ' + model)
        else:
            logger.error('Failed to connect to APC, model ' + model)
            return False
        for port_num in port_list:
            logger.info('Switch off the power on port :' + port_num)
            # port_num = 10
            operation = "off"
            val = con.SetPowerStatePort(port_num, operation)
            if val == None:
                logger.error('Failed to set power state of port number '
                             + str(port_num) + ' with : ' + operation)
                return False
            else:
                logger.info('Power state of port number '
                            + str(port_num) + ' set to : ' + operation)
            val = con.GetPowerStatePort(port_num)
            if val == None:
                logger.error(
                    'Failed to get power state of port number ' + str(port_num))
            else:
                logger.info(
                    'Power state of port number ' + str(port_num) + ' is : ' + val)

        time.sleep(2)
        for port_num in port_list:
            logger.info('Switch On the power on port :' + port_num)
            operation = "on"
            val = con.SetPowerStatePort(port_num, operation)
            if val == None:
                logger.error('Failed to set power state of port number '
                             + str(port_num) + ' with : ' + operation)
                return False
            else:
                logger.info(
                    'Power state of port number ' + str(port_num) + ' set to : ' + operation)
            val = con.GetPowerStatePort(port_num)
            if val == None:
                logger.error(
                    'Failed to get power state of port number ' + str(port_num))
            else:
                logger.info(
                    'Power state of port number ' + str(port_num) + ' is : ' + val)

        ''' reconnecting to mgmt handle '''
        mgmt_detail_obj = config.mgmtdetail
        bmc_ip = mgmt_detail_obj.bmc_mgmt_ip
        bmc_login = mgmt_detail_obj.bmc_login
        bmc_passwd = mgmt_detail_obj.bmc_password

        res = self.verify_host_up(bmc_ip, wait_time=500)
        if res is not True:
            logger.error('After AC cycle, failed to ping BMC mgmt IP')
            return False
        else:
            logger.info('After AC cycle, able to ping BMC mgmt IP')
        self.handle = LinuxUtils(bmc_ip, bmc_login, bmc_passwd)
        self.handle.connect()
        return True

    def verify_host_up(self, hostname='default', wait_for_ping_fail=True, wait_time=500):
        '''
        Procedure to verify if bmc/host is UP using ping
        Parameter:
            hostName : IP or hostname of the server to be checked
            waitForPingFail : If true, will wait for ping to fail and then back up
                        If False, will return True in case host is responding
            wait_time : Max time attempted to check host's availability
        Return:
            True  : Success
            False : Failure
        '''
        pkt_count = 3
        time_to_sleep = 10
        ping_failed = False
        host_rebooted = False
        # sleep for wait_time timeout, default is
        max_wait_time = time.time() + wait_time
        if hostname == 'default':
            logger.info(
                'Will use GlobalVariable for hostname : ' + str(hostname))
        else:
            logger.info(
                'Will verify for a provided host address : ' + str(hostname))
        try:
            while True:
                # subpocess.check_output('/usr/bin/which ping')
                png_path = 'ping'
                logger.info('Ping tool path : ' + png_path)
                cmdstr = png_path + ' -c ' + str(pkt_count) + ' ' + hostname
                logger.info('Command: ' + cmdstr)
                exceptioncaught = False
                try:
                    pngoutput = subprocess.check_output(cmdstr, shell=True,
                                                        stderr=subprocess.STDOUT)
                except:
                    # dump_error_in_lib()
                    pngoutput = 'not all pings were successful'
                    exceptioncaught = True
                logger.info('Output : ' + str(pngoutput))
                obj = re.search('[0-9]+ packets transmitted, [0-9]+ received, 0% packet loss',
                                str(pngoutput))
                logger.info('Object: ' + str(obj))
                if obj != None and exceptioncaught != True:
                    logger.info('Ping successful')
                    if ping_failed == False and wait_for_ping_fail == True:
                        logger.info('Ping failure didnt happen yet')
                    else:
                        logger.info('Host has rebooted and back up')
                        host_rebooted = True
                        break
                else:
                    logger.info('Ping failed')
                    ping_failed = True
                    time.sleep(time_to_sleep)
                if time.time() > max_wait_time:
                    logger.info('Maximum timeout reached')
                    break
                else:
                    logger.info('Will continue to wait')
                    continue
            if host_rebooted == True:
                logger.info('Host successfully rebooted')
                return True
            else:
                logger.error('Host is not up')
                return False
        except:
            dump_error_in_lib()
            return False

    def HuuUpdate(self, huu_update_info, node='1'):
        '''
        Method to update CIMC using HUU iso
        '''
        mgmt_detail_obj = self.config.mgmtdetail
        bmc_ip = mgmt_detail_obj.bmc_mgmt_ip
        bmc_login = mgmt_detail_obj.bmc_login
        bmc_passwd = mgmt_detail_obj.bmc_password
        pl = mgmt_detail_obj.platform
        platformHash = {
            'dn1': 'delnorte1',
            'dn2': 'delnorte2',
            'pl1': 'plumas1',
            'pl2': 'plumas2',
            'mad': 'madeira'
        }
        platform = platformHash[pl]

        logDir = easypy.runtime.directory
        logger.info('Log Dir is:' + logDir)
        release = huu_update_info[0]
        version = huu_update_info[1]
        node = '1'

        logger.info('**************************************')
        logger.info('HUU Update params are:')
        logger.info("platform {}, release {}, version {}".format(platform, release, version))
        logger.info('**************************************')

        arg = "/data/home/releng/py/bin/python /auto/svbudata-home-bgl/releng/cluster_switch.main/rm_automation/tools/./upgradeWrapper1.py --testbed\
         '{}' --cimcuserName '{}' --cimcPassword '{}' --updateComponent '{}' --platform '{}' --release '{}'\
           --iso '{}' --logDir '{}' --serverNode {}".format(bmc_ip, bmc_login, bmc_passwd,
                                                            'all', platform, release, version,
                                                            logDir, node)
        logger.info('upgrade command: ' + str(arg))
        p = subprocess.Popen(arg, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        logger.info('Upgrade completed')
        logger.info('stdout: ' + str(out))
        logger.info('stderr: ' + str(err))

        if re.search("Firmware update successful for CIMC  NOt found", str(out)):
            logger.error('CIMC update not found, HUU update failed')
            update = False
        elif re.search("Firmware update successful for CIMC", str(out)):
            logger.info('INFO : output_message : Firmware update successful for CIMC')
            update = True
        else:
            logger.error('ERROR: output_message : Firmware update successful for CIMC  NOt found')
            update = False

        if update is False:
            logger.error('HUU Update Failed')
            return False
        else:
            logger.info('HUU upgrade success')
            # After HUU update connect back to CIMC
            self.handle = LinuxUtils(bmc_ip, bmc_login, bmc_passwd)
            self.handle.connect()
            return True

    def set_techsupport_param_value(self, param, new_value):
        '''
        Procedure to set tech-support attribute values
        Parameter:
            handle: connection handle of cimc
            param: tech-support parameter value
            new_value: New desired value to set
        Return:
            True  : Success
            False : Failure
        '''
        logger.info('Setting tech-support parameter attribute values:')
        logger.info('Attribute: ' + str(param) + ' Value: ' + str(new_value))
        self.handle.execute_cmd_list('top', 'scope cimc', 'scope tech-support')
        out = self.handle.execute_cmd(
            'set ' + str(param) + ' ' + str(new_value), wait_time=8)
        match = re.search('invalid|exceeding|incomplete|Valid value|Maximum|cannot be used',
                          out, re.I)
        if match is not None:
            logger.error(
                'Failed to execute command; got error as: ' + str(match))
            return False
        commit_out = self.handle.execute_cmd('commit')
        if re.search('ERROR', commit_out, re.IGNORECASE):
            logger.info('Unable to set parameter ' +
                        str(param) + ' to ' + str(new_value) + ' : ' + str(commit_out))
            self.handle.execute_cmd('discard')
            return False
        return True

    def get_techsupport_param_value(self, param):
        '''
        Procedure to get tech-support attribute values
        Parameter:
            handle: connection handle of cimc
            param: tech-support parameter value
        Return:
            Value of the parameter that is asked
            False: Failure
        '''
        try:
            logger.info(
                'Fetching tech-support attribute param value: ' + str(param))
            self.handle.execute_cmd_list(
                'top', 'scope cimc', 'scope tech-support')
            out = self.handle.execute_cmd('show detail', wait_time=6)
            return re.search(param + ': ([^\r\n]+)', out).group(1)
        except:
            dump_error_in_lib()
            return False

    def check_techsupport_param_value(self, param, expected_value):
        '''
        Procedure to validate tech-support attribute values
        Parameter:
            handle: connection handle of cimc
            param: tech-support parameter value
            expected_value: Value which we expect BMC to report back
        Return:
            True  : Success
            False : Failure
        '''
        try:
            if self.get_techsupport_param_value(param) is expected_value:
                return True
            else:
                return False
        except:
            dump_error_in_lib()
            return False

    def start_tech_support(self):
        '''
        Procedure to start tech-support
        Parameter:
            handle: connection handle of cimc
        Return:
            True  : Success
            False : Failure
        '''
        try:
            self.handle.execute_cmd_list(
                'top', 'scope cimc', 'scope tech-support')
            out = self.handle.execute_cmd('start', wait_time=8)
            logger.info(out)
            if "Tech Support upload started" in out:
                logger.info(
                    'Tech Support Upload start command was issued successfully')
                return True
            match = re.search('invalid command detected|Already an upload is in \
                               progress|Hostname/IP Address|is not reachable', out, re.I)
            if match is not None:
                logger.error('Can not issue tech-support start command')
                return False
        except:
            dump_error_in_lib()
            return False

    def has_techsupport_started(self):
        '''
        Procedure to check whether tech-support has started collecting data
        Parameter:
            handle: connection handle of cimc
        Return:
            True  : Success
            False : Failure
        '''
        try:
            self.handle.execute_cmd_list(
                'top', 'scope cimc', 'scope tech-support')
            out = self.handle.execute_cmd('show detail', wait_time=6)
            logger.info(out)
            out = re.search('remote-status: ([^\r\n]+)', out).group(1)
            if out == "COLLECTING":
                logger.info('The Update is in progress')
                return True
            elif out == "COMPLETED":
                logger.error(
                    'The tech-support status not started after start command was issued')
                return False
        except:
            dump_error_in_lib()
            return False

    def wait_for_techsupport_to_finish(self, wait_time=1200):
        '''
        Procedure to wait until tech-support is completed
        Parameter:
            handle: connection handle of cimc
            Optional Param:
                wait_time: Maximum time to wait for tech-support to complete
        Return:
            True  : Success
            False : Failure
        '''
        try:
            max_wait_time = time.time() + wait_time
            while time.time() < max_wait_time:
                out = self.get_techsupport_param_value('progress')
                if out == "100":
                    logger.info('Successfully uploaded tech-support data')
                    return True
                elif 'Remote_Upload_Error' in out:
                    logger.error('Upload error happened, will exit')
                    return False
                time.sleep(10)
                logger.info('Will continue to wait')
            logger.info(
                'Exceeded max wait time ' + str(max_wait_time) + ' seconds')
            return False
        except:
            dump_error_in_lib()
            return False

    def start_and_wait_for_ts_to_finish(self):
        '''
        Wrapper procedure to start and wait for tech-support to complete
        Parameter:
            handle: connection handle of cimc
        Return:
            True  : Success
            False : Failure
        '''
        try:
            if self.start_tech_support() is False:
                logger.error('Tech-support start command failed')
                return False
            if self.has_techsupport_started() is False:
                logger.error(
                    'The tech-support status not started after start command was issued')
                return False
            if self.wait_for_techsupport_to_finish() is False:
                logger.error(
                    "Tech support upload did not finish in max timeout seconds")
                return False
            return True
        except:
            dump_error_in_lib()
            return False

    def upload_techsupport_data(self, protocol='None'):
        '''
        Wrapper procedure to start and wait for tech-support to complete
        Parameter:
            handle: connection handle of cimc
            Optional param:
                protocol: one of the protocol (currently supported 'tftp')
        Return:
            True  : Success
            False : Failure
        '''
        path_value = "remote-path"
        tftp_ip = "remote-ip"
        status_value = "remote-status"
        remore_protocol = "remote-protocol"
        time_stamp = strftime("%Y-%m-%d_%H-%M-%S")
        tftp_tmp_auto_file_name = 'tmpAutomation-testCase-bmc-'
        tftp_tmp_auto_file_name += str(time_stamp)
        tftp_tmp_auto_file_name += '.tar.gz'
        logger.info(
            'Unique file name on TFTP server: ' + str(tftp_tmp_auto_file_name))
        '''Set tech-support remote-path value'''
        if self.set_techsupport_param_value(path_value, tftp_tmp_auto_file_name) is False:
            logger.error(
                'Failed to set remote-path value:' + str(tftp_tmp_auto_file_name))
            return False
        '''set tech-support remote-ip parameter value'''
        '''Need to fetch this IP from config file'''
        remote_server_ip = '10.126.164.31'
        if self.set_techsupport_param_value(tftp_ip, remote_server_ip) is False:
            logger.error(
                'Failed to set remote-ip value:' + str(remote_server_ip))
            return False
        '''set remote protocol value'''
        if protocol is 'None':
            protocol = 'tftp'
        else:
            protocol = protocol
        '''Set tech-support remote-protocol parameter value'''
        if self.set_techsupport_param_value(remore_protocol, protocol) is False:
            logger.error(
                'Failed to set remote-protocol value:' + str(protocol))
            return False
        stage_value = self.get_techsupport_param_value(status_value)
        if stage_value == 'COLLECTING' or stage_value == 'UPLOADING':
            logger.error(
                'BMC tech support progress is' + str(stage_value) + 'Can not continue')
            return False
        if self.start_and_wait_for_ts_to_finish() is False:
            return False
        self.ts_file_path = tftp_tmp_auto_file_name

    def get_cimc_sel_log_latest_event(self, log_scope='cimc'):
        '''
        Procedure to get Latest Log entry before an event
        Return:
            returns latest event on  : Success
            empty string if no CIMC logs : Failure
            Author : Jagadish Chanda <jchanda@cisco.com>
        '''
        try:
            logger.info("Inside get log proc")
            if log_scope == 'cimc':
                self.handle.execute_cmd_list('top', 'scope cimc', 'scope log')
            else:
                self.handle.execute_cmd_list('top', 'scope sel')
            log_before_event = self.handle.execute_cmd("show entries", wait_time=20)
            if '--More--' in log_before_event:
                log_output = self.handle.execute_cmd("R", wait_time=10)
                log_before_event += log_output
                while True:
                    if '--More--' in log_output:
                        log_output = self.handle.execute_cmd("R", wait_time=10)
                        log_before_event += log_output
                        log_output = ''
                    else:
                        break

            log_before_event = log_before_event.split("\n")
            if len(log_before_event) > 3:
                return log_before_event[3]
            else:
                logger.info("There may be no CIMC Log entries before the event")
                return ""
        except:
            dump_error_in_lib()
            return False

    def clear_cimc_sel_logs(self, log_scope='cimc'):
        '''
        Procedure to clear CIMC or SEL logs
        Parameter:
            log_scope: <cimc | sel>
        Return:
            True: On successfully clearing of logs
            False:On failed to clear logs
        '''
        if log_scope == 'cimc':
            self.handle.execute_cmd_list('top', 'scope cimc', 'scope log')
        else:
            self.handle.execute_cmd_list('top', 'scope sel')
        out = self.handle.execute_cmd('clear')
        if 'Continue' in out:
            self.handle.execute_cmd('y')
        elif 'Clear the Cisco IMC log' in out:
            self.handle.execute_cmd('y')
        else:
            logger.warning('Failed to clear the logs')
            return False
        logger.info('Successfully cleared the logs')
        return True

    def check_cimc_sel_log_diff_event(self, log_before_event,
                                      log_scope='cimc', severity=["Critical"]):
        '''
        Procedure to check cimc and sel log
            SEL : If the "log_scope" parameter should be sel and it will
                  check for log diff and if any new log found it will return false

            CIMC : If log_scope parameter is cimc or by default it will get check cimc log.
                   To check severity in cimc log pass the severity parameter as list with all
                   desired severity.
                   By default it will check for Critical event.
        Parameters:
            log_before_event: Latest Log entry before an event
            log_scope : cimc or sel (default cimc)
            severity : List severity to be checked.(default Critical events)

        Return:
            True if mention severity not found in the log: Success
            False : Failure
        Author : Jagadish Chanda <jchanda@cisco.com> and Suren Kumar Moorthy<suremoor@cisco.com>
        '''

        try:
            if log_scope == 'cimc':
                self.handle.execute_cmd_list('top', 'scope cimc', 'scope log')
            else:
                self.handle.execute_cmd_list('top', 'scope sel')
            log_after_event = self.handle.execute_cmd('show entries', wait_time=20)
            if '--More--' in log_after_event:
                log_output = self.handle.execute_cmd("R")
                log_after_event += log_output
                while True:
                    if '--More--' in log_output:
                        log_output = self.handle.execute_cmd("R")
                        log_after_event += log_output
                    else:
                        break
            log_after_event = log_after_event.split("\n")
            diff_list = []
            if len(log_after_event) > 3:
                for i in range(3, len(log_after_event)):
                    if log_after_event[i].strip() not in log_before_event.strip():
                        diff_list.append(log_after_event[i])
                    else:
                        break
            else:
                logger.error("Failed to fetch the log difference")
                return False
            logger.info("######### Diff List ###################")
            logger.info(diff_list)
            logger.info("#########################################")
            if 'sel' in log_scope or 'cimc' in log_scope:
                if len(diff_list) > 0:
                    logger.info(diff_list)
                    logger.warning("Found Difference in sel/cimc log")

            log_found = 0
            logger.info("######### Log Diff ##############")
            logger.info(diff_list)
            logger.info("#################################")
            if len(severity) > 1:
                sev_reg = "|".join(severity)
            elif len(severity) == 1:
                sev_reg = severity[0]
            else:
                sev_reg = 'Critical'
            rege = r'\d{2}\:\d{2}\:\d{2}\s+\w{3}\s+(?:' + sev_reg + ")"
            for log in diff_list:
                if re.search(rege, log):
                    logger.error(log)
                    log_found = 1
            if log_found == 1:
                logger.error("Found called severity in log")
                return False
            else:
                return True
        except:
            dump_error_in_lib()
            return False

    def get_overall_health_status(self):
        '''
        Procedure to get over all health status
        '''
        return self.get_led_status()

    def get_led_status(self, led="LED_HLTH_STATUS"):
        '''
        Procedure to get led state of server
        Parameter:
        led: Default - LED_HLTH_STATUS
             or
             Pass the appropriate led name to get the status
        Return:
            Led status: Success
            False : Failure

        Author: Suren kumar Moorthy
        '''
        logger.info('Getting the LED status')

        try:
            out = self.handle.execute_cmd_list(['top', 'scope chassis',
                                                'show led detail'], wait_time=10)
            logger.info(out)
            regex = r'name\:\s*' + led + \
                r'\s*state\s*\:\s*\w+\s*color\:\s*(\w+)'
            return re.search(regex, out).group(1)
        except:
            dump_error_in_lib()
            return False

    def validate_cdn_techsupport(self, config):
        con = ConfigParser()
        tftp_config = con.load_common_config().tftp_share
        remote_ip = tftp_config.tftp_server_ip
        remote_user = tftp_config.tftp_user
        remote_passwd = tftp_config.tftp_password
        tftp_root_dir = tftp_config.tftp_root_path
        tftp_handle = LinuxUtils(remote_ip, remote_user, remote_passwd)
        tftp_handle.connect()
        ts_path = tftp_root_dir + '/TechSupport/'
        tftp_handle.execute_cmd('mkdir -p ' + ts_path)
        tftp_handle.execute_cmd('chmod 777 ' + ts_path)
        tftp_handle.execute_cmd(
            'tar -xzvf /TFTP_DIR/' + self.ts_file_path + ' ' + "-C" + ' ' + ts_path)

        platform_type = config.mgmtdetail.platform_series
        if platform_type == 'M5':
            cdn_ts = tftp_handle.execute_cmd('cat' + ' ' + ts_path + 'mnt/jffs2/BIOS/bt/BiosTech.log \
                                        | grep "Patched eNIC Name"')
        else:
            cdn_ts = tftp_handle.execute_cmd('cat' + ' ' + ts_path + 'var/nuova/BIOS/BiosTech.txt \
                                        | grep "Patched eNIC Name"')
        time.sleep(20)
        tftp_handle.disconnect()
        cdn_from_tsr = re.findall(r'=\s+([^\r\n\'\s]+)', cdn_ts)
        logger.info('CDN info from Tech-support data')
        logger.info(cdn_from_tsr)

        '''Getting CDN name from CIMC'''
        logger.info('Fetching CDN name from CIMC CLI')
        vic_list = config.inventory_detail
        vic_obj = VicLib(self, config)
        for vic in vic_list:
            slot_no = vic.slot_number

            out = vic_obj.cimc_cdn_mac_dict(slot_no)
            cnd_from_cimc = []
            for cdn_name in out.values():
                cnd_from_cimc.append(cdn_name)
            logger.info('CDN name from CIMC')
            logger.info(cnd_from_cimc)

            for val in cdn_from_tsr:
                if val not in cnd_from_cimc:
                    logger.info(
                        "From CIMC CDN name are not same as TSR CDN name")
                    return False
        return True

    def remove_techsupport_file(self):
        '''
        Procedure to remove the tech-support file
        Returns:
            True: on success
            False: on failure
        '''
        try:
            logger.info('Deleting tech-support file: ' + self.ts_file_path)
            con = ConfigParser()
            tftp_config = con.load_common_config().tftp_share
            remote_ip = tftp_config.tftp_server_ip
            remote_user = tftp_config.tftp_user
            remote_passwd = tftp_config.tftp_password
            handle = LinuxUtils(remote_ip, remote_user, remote_passwd)
            handle.connect()
            handle.execute_cmd('rm -f ' + '/TFTP_DIR/' + self.ts_file_path)
            handle.disconnect()
        except:
            dump_error_in_lib()

    def get_sensor_data(self, type='voltage'):
        output = self.handle.execute_cmd_list(
            'top',
            'scope sensor',
            'show ' + type)
        sensor_list = output.splitlines()
        sensor_out = []
        for sensor in sensor_list:
            if sensor != sensor_list[0] and sensor != sensor_list[1] and sensor != sensor_list[
                    2] and sensor != sensor_list[3] and sensor != sensor_list[4]:
                sensor_data = []
                for val in sensor.split(' '):
                    if val != '':
                        sensor_data.append(val)

                sensor_out.append(sensor_data)

        logger.info('sensor out is')
        logger.info(sensor_out)
        return sensor_out

    def verfiy_sol_screen(self, config):
        sol_enabled = self.bios_util_obj.get_common_token_value("enabled", "sol")
        logger.info("Sol enabled value is" + sol_enabled)
        if 'no' in sol_enabled:
            status = self.bios_util_obj.set_common_token_value("enabled", "yes", "sol", commit_wait=120)
            if status is False:
                logger.error("Failed to set sol enabled to yes")
                return False
        sol_out = self.handle.execute_cmd_list('top', 'scope sol', 'connect host', "\n")
        logger.info(sol_out)
        host_info_obj = config.host_info[0].host_detail
        prompt = host_info_obj.os_host_name
        logger.info("Prompt " + prompt)
        out = self.handle.execute_cmd_list(chr(24))
        logger.info(out)
        if prompt in sol_out:
            logger.info("Successfully verified sol")
            return True
        elif re.search(r'(login)|(password)\:', sol_out).group(0):
            logger.info("Successfully verified sol matched login or password prompt")
            return True
        else:
            logger.error("Failed to verify sol")
            return False

    def get_platform_name(self, plat):
        plat_dict = {"dn1": "delnorte1"}
        return plat_dict[plat]

    def get_release_note_content(self, config):
        try:
            mgmt_detail_obj = config.mgmtdetail
            plat = mgmt_detail_obj.platform
            platform = self.get_platform_name(plat)
            build = os.environ["BUILD"]
            huu_image = os.environ["HUU_IMAGE"]
            if not build:
                logger.error("Build is not set in environment variable")
                return False
            if not huu_image:
                logger.error("HUU IMAGE is not set in environment variable")
                return False
            huu_iso_file = "/var/www/html/HUU_Sanity/systemupgrade/isos/" + \
                platform + "/" + build + "/" + huu_image
            logger.info("HUU FILe: " + huu_iso_file)
            host = LinuxUtils('10.127.45.20', 'root', 'HuuWelcome123')
            host.connect()
            if "No such file or directory" in host.execute_cmd("ls " + huu_iso_file):
                logger.error("HUU file not found in filer")
                return False
            # Mouting ISO
            logger.info("Mouting ISO" + huu_iso_file)
            mount_folder = "/mnt/" + \
                re.search(r'(.*?)\.iso', huu_image).group(1)
            logger.info("Mount Foleder" + mount_folder)
            host.execute_cmd("mkdir " + mount_folder)
            # Check mount folder
            if "No such file or directory" in host.execute_cmd("ls " + mount_folder):
                logger.error("mount folder is not found in filer")
                return False
            host.execute_cmd(
                "mount -o loop " + huu_iso_file + " " + mount_folder)
            if "No such file or directory" in host.execute_cmd("ls " + mount_folder + "/TOC*.xml"):
                logger.error("TOC file not found")
                return False
            toc_out = host.execute_cmd("cat " + mount_folder + "/TOC*.xml")
            host.disconnect()
            return toc_out
        except:
            dump_error_in_lib()
