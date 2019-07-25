import logging
import re
import sys
import telnetlib
import time
import requests

import cid
from common_utils import dump_error_in_lib

logger = logging.getLogger(__name__)

__author__ = 'Balamurugan Ramu <balramu@cisco.com>'
__copyright__ = 'Copyright 2016, Cisco Systems'
__email__ = 'balramu@cisco.com'
__date__ = 'Sep 20,2016'
__version__ = 1.0


class TelnetUtil():

    def __init__(self, ip, term_username=None, term_password=None, host_username=None,
                 host_password=None, mgmnt_port=None, host_port=None, server_type=None):
        self.ip = ip
        self.term_username = term_username
        self.term_password = term_password
        self.host_username = host_username
        self.host_password = host_password
        self.mgmnt_port = mgmnt_port
        self.host_port = host_port
        self.server_type = server_type
        self.term_handle = None
        self.mgmnt_conn_handle = None
        self.host_conn_handle = None

    def connect_to_terminal_srvr(self):
        telnet_handle = telnetlib.Telnet(self.ip.encode('ascii'))
        logger.info(telnet_handle.read_until(b"Username: "))
        logger.info(telnet_handle.write(self.term_username.encode('ascii') + b"\n"))
        logger.info(telnet_handle.read_until(b"Password: "))
        logger.info(telnet_handle.write(self.term_password.encode('ascii') + b"\n"))
        self.term_handle = telnet_handle
        return self.term_handle

    def connect_to_mgmnt(self):
        try:
            logger.info('Console IP {} and Port {}'.format(self.ip, self.mgmnt_port))
            telnet_handle = telnetlib.Telnet(
                self.ip.encode('ascii'), self.mgmnt_port)
            telnet_handle.set_debuglevel(10)
            self.mgmnt_conn_handle = telnet_handle
            self.mgmnt_conn_handle.write(b'\n')
            self.mgmnt_conn_handle.write(b'\n')
            time.sleep(3)
            cur_mode = self.get_cimc_serial_mode()
            if cur_mode == None:
                # send cntr+C signal to return to sldp or help prompt
                self.mgmnt_conn_handle.write(b'\x03')
                self.connect_debug_shell_serial(connectShell='None', sldp_enabled='yes')
            elif cur_mode == 'responseKeyMode':
                self.connect_debug_shell_serial(connectShell='None')
            elif cur_mode == 'sldpMode' or cur_mode == 'helpMode':
                self.connect_debug_shell_serial(connectShell='None', sldp_enabled='yes')
            return self.mgmnt_conn_handle
        except:
            logger.warning('Entering exception block in: connect_to_mgmnt')

            dump_error_in_lib()

            tem_handle = self.connect_to_terminal_srvr()
            # Have to handle the server_Type here
            if self.server_type == None or 'cisco' in self.server_type:
                i = 0
                while i < 4:
                    tem_handle.write(
                        b'clear line ' + str(self.mgmnt_port)[2:].encode('ascii') + b'\n')
                    tem_handle.read_until(b'[confirm]', 5).decode('ascii')
                    tem_handle.write(b'\n')
                    i += 1
                    time.sleep(3)
                    logger.info('in while with loop count' + str(i))

            try:
                telnet_handle = telnetlib.Telnet(
                    self.ip.encode('ascii'), self.mgmnt_port)
                telnet_handle.set_debuglevel(10)
                self.mgmnt_conn_handle = telnet_handle
                self.mgmnt_conn_handle.write(b'\n')
                self.mgmnt_conn_handle.write(b'\n')
                time.sleep(3)
                if self.get_cimc_serial_mode() == 'responseKeyMode':
                    self.connect_debug_shell_serial(connectShell='None', sldp_enabled='yes')

                return self.mgmnt_conn_handle
            except:
                dump_error_in_lib()
                logger.error('Connection issue check terminal ')
                return None

    def change_default_password(self):
        logger.info("Changing the default password")

        original_password = 'password'
        mgmnt_password = 'Topspin515'

        try:
            self.mgmnt_conn_handle.read_until(b'Enter current password: ', 5)
            logger.info('Entering current password:')
            self.mgmnt_conn_handle.write(
                original_password.encode('ascii') + b'\n')

            self.mgmnt_conn_handle.read_until(b'Enter new password: ', 5)
            logger.info('Entering new password:')
            self.mgmnt_conn_handle.write(
                mgmnt_password.encode('ascii') + b'\n')

            self.mgmnt_conn_handle.read_until(b'Re-enter new password: ', 3)
            logger.info('Re-Entering new password:')
            self.mgmnt_conn_handle.write(
                mgmnt_password.encode('ascii') + b'\n')

            self.mgmnt_conn_handle.read_until(b'Updating password...', 5)
            self.mgmnt_conn_handle.read_until(
                b'Password updated successfully.', 5)
            logger.info('Password Successfully Changed')

            return True

        except:
            dump_error_in_lib()
            return False

    def connect_to_host_serial(self):
        logger.info('Connecting to host console terminal')
        try:
            telnet_handle = telnetlib.Telnet(
                self.ip.encode('ascii'), self.host_port)
            telnet_handle.set_debuglevel(10)
            self.host_conn_handle = telnet_handle
            self.host_conn_handle.write(b'\n')
            logger.info('Successfully connected host serial')

        except:
            dump_error_in_lib()
            tem_handle = self.connect_to_terminal_srvr()
            # Have to handle the server_Type here
            if self.server_type == None or 'cisco' in self.server_type:
                i = 0
                while i < 4:
                    logger.info(tem_handle.write(
                        b'clear line ' + str(self.host_port)[2:].encode('ascii') + b'\n'))
                    logger.info(tem_handle.read_until(b'[confirm]', 5).decode('ascii'))
                    logger.info(tem_handle.write(b'\n'))
                    i += 1
                    time.sleep(3)
                    logger.info('in while with loop count' + str(i))

            try:
                telnet_handle = telnetlib.Telnet(
                    self.ip.encode('ascii'), self.host_port)
                telnet_handle.set_debuglevel(10)
                self.host_conn_handle = telnet_handle
                self.host_conn_handle.write(b'\n')
                logger.info('Successfully connected to host console terminal')
            except:
                dump_error_in_lib()
                logger.error('Connection issue check terminal ')
                return None

        host_handle = self.host_conn_handle
        host_handle.write(b'\r\n')
        return host_handle

    def connect_to_host(self):
        logger.info('Connecting to host console terminal')
        try:
            telnet_handle = telnetlib.Telnet(
                self.ip.encode('ascii'), self.host_port)
            telnet_handle.set_debuglevel(10)
            self.host_conn_handle = telnet_handle
            self.host_conn_handle.write(b'\n')
            logger.info('Successfully connected host serial')
        except:
            dump_error_in_lib()

            tem_handle = self.connect_to_terminal_srvr()
            # Have to handle the server_Type here
            if self.server_type == None:
                i = 0
                while i < 4:
                    tem_handle.write(
                        b'clear line ' + str(self.host_port)[2:].encode('ascii') + b'\n')
                    tem_handle.read_until(b'[confirm]', 5).decode('ascii')
                    tem_handle.write(b'\n')
                    i += 1
                    time.sleep(3)

            try:
                telnet_handle = telnetlib.Telnet(
                    self.ip.encode('ascii'), self.mgmnt_port)
                telnet_handle.set_debuglevel(10)
                self.host_conn_handle = telnet_handle
                self.host_conn_handle.write(b'\n')

            except:
                dump_error_in_lib()
                return None

        host_handle = self.host_conn_handle
        host_handle.write(b'\r\n')

        try:
            logger.info('Terminating existing session')
            logger.info(host_handle.read_until(b'login:', 5))
            host_handle.write(self.host_username.encode('ascii') + b'\n')
            logger.info(host_handle.read_until(b'Password:', 5))
            host_handle.write(self.host_password.encode('ascii') + b'\n')
            logger.info(host_handle.read_lazy())
        except:
            dump_error_in_lib()

            tem_handle = self.connect_to_terminal_srvr()
            # Have to handle the server_Type here
            if self.server_type == None:
                i = 0
                while i < 4:
                    tem_handle.write(
                        b'clear line ' + str(self.port)[2:].encode('ascii') + b'\n')
                    tem_handle.read_until(b'[confirm]', 5).decode('ascii')
                    tem_handle.write(b'\n')
                    i += 1
            try:
                logger.info(host_handle.read_until(b'login:', 5))
                host_handle.write(self.host_username.encode('ascii') + b'\n')
                logger.info(host_handle.read_until(b'Password:', 5))
                host_handle.write(self.host_password.encode('ascii') + b'\n')
                logger.info(host_handle.read_lazy())

            except:
                dump_error_in_lib()
                return None

        return host_handle

        '''
        time.sleep(2)
        host_handle.write(b'reboot\n')
        print(host_handle.read_until(b'<F2> Setup', 720))
        host_handle.write(b'\x1b2')
        host_handle.write(b'\x1b2')
        host_handle.write(b'\x1b2') 
        print(host_handle.read_lazy())
    '''

    def disconnect(self):
        if self.mgmnt_conn_handle != None:
            self.mgmnt_conn_handle.close()
        if self.term_handle != None:
            self.term_handle.close()
        if self.host_conn_handle != None:
            logger.info('Terminating host console handle')
            self.host_conn_handle.close()

    def execute_cmd_serial(self, cmds, wait_time=3):
        self.cmds = cmds
        self.mgmnt_conn_handle.write(self.cmds.encode('ascii'))
        self.mgmnt_conn_handle.write(b'\n')
        time.sleep(wait_time)
        return self.mgmnt_conn_handle.read_very_eager().decode('utf-8')

    def execute_cmd_serial_host(self, cmds, wait_time=10):
        self.cmds = cmds
        logger.info('Waiting before executing command :' + str(cmds))
        time.sleep(wait_time)
        self.host_conn_handle.write(self.cmds.encode('ascii'))
        self.host_conn_handle.write(b'\n\r')
        time.sleep(wait_time)
        output = ''
        try:
            output = self.host_conn_handle.read_very_eager().decode('utf-8')
        except:
            logger.error(sys.exc_info()[0])
        return output

    def get_cimc_serial_mode(self):
        """
        Procedure to return current cimc serial mode

        Return Value: On Success it will returns either of one 'linuxMode' 'cliMode' 'debugMode'
                      None in case of failure
        """
        logger.info('Calling get_cimc_serial_mode method')
        try:
            time.sleep(1)
            out = self.execute_cmd_serial('\n')
            time.sleep(2)

            linux_prompt = ':~]$'
            cli_prompt1 = 'bmc#'
            cli_prompt2 = ' #'
            cli_prompt3 = '# '
            cli_prompt4 = '--More--'
            help_prompt = '[ help ]#'
            response_key_prompt = 'ResponseKey#>'
            mode = None
            change_passwd_prompt = 'Enter current password: '
            sldp_prompt = '[ sldp ]#'

            if linux_prompt in out:
                mode = 'linuxMode'
            elif help_prompt in out:
                mode = 'helpMode'
            elif sldp_prompt in out:
                mode = 'sldpMode'
            elif response_key_prompt in out:
                mode = 'responseKeyMode'
            elif change_passwd_prompt in out:
                mode = 'changePasswdMode'
            elif cli_prompt1 in out or cli_prompt2 in out or \
                    cli_prompt3 in out or cli_prompt4 in out:
                mode = 'cliMode'
            else:
                mode = None
            logger.info('CIMC serial in: ' + str(mode))
            return mode

        except:
            logger.warning('Exception in def get_cimc_serial_mode')
            dump_error_in_lib()

    def set_bmc_serial_mode(self, mode_type):
        '''
        Procedure to set, cimc serial in linuxMode or cliMode or debugMode

        Return Value: True on Success
                      None in case of failure
        '''
        mode = self.get_cimc_serial_mode()
        self.mode_type = mode_type

        if self.mode_type == mode:
            return True

        # Return CIMC linux prompt
        elif self.mode_type == 'linuxMode':
            if mode == self.mode_type:
                return True

            elif mode == 'cliMode':
                self.execute_cmd_serial('top')
                self.execute_cmd_serial('exit')
                if self.get_cimc_serial_mode() == self.mode_type:
                    return True

            elif mode == 'helpMode':
                self.connect_debug_shell_serial(connectShell='None')
                if self.get_cimc_serial_mode() == self.mode_type:
                    return True

        # Return CIMC CLI prompt
        elif self.mode_type == 'cliMode':
            if mode == self.mode_type:
                return True

            elif mode == 'linuxMode':
                self.execute_cmd_serial('export USER=root privileges=511')
                out = self.execute_cmd_serial('/usr/cli/pmcli')
                if 'Enter current password:' in out:
                    logger.info('linuxMode: BMC password need to be changed')
                    if self.change_default_password() is False:
                        logger.error('Failed to change the Administrator password')
                        return False
                if self.get_cimc_serial_mode() == self.mode_type:
                    return True

            elif mode == 'helpMode':
                self.connect_debug_shell_serial(connectShell='None')
                self.execute_cmd_serial('export USER=root privileges=511')
                out = self.execute_cmd_serial('/usr/cli/pmcli')
                if 'Enter current password:' in out:
                    logger.info('helpMode: BMC password need to be changed')
                    if self.change_default_password() is False:
                        logger.error('Failed to change the Administrator password')
                        return False
                if self.get_cimc_serial_mode() == self.mode_type:
                    return True
                elif mode == 'changePasswdMode':
                    logger.info('BMC password need to be changed')
                    if self.change_default_password() is True:
                        return True
        return False

    def connect_debug_shell_serial(self, connectShell=None, sldp_enabled='yes'):
        logger.info('Connecting CIMC Debug Shell')
        # sldp_enabled variable can be moved to env variable or Job file

        if connectShell != 'None':
            logger.info('connect debug-shell')
            self.execute_cmd_serial('connect debug-shell')

        time.sleep(2)
        if sldp_enabled != 'yes':
            output = self.execute_cmd_serial('load debug plugin')

            data = ''
            responsekey = ''
            r = ''

            logger.info('Trying CIMC Shell Access Key Generator')
            line_list = re.split("\r\n", output)
            for line in line_list:
                if 'ChallengeKey#>' in line:
                    data = line.replace('ChallengeKey#> ', '')
                    r = requests.get(
                        'http://savbu-swbmc-vbld1.cisco.com/CIMC-key/generate?key=' + data)

            key_output = r.text.split('\n')
            for line in key_output:
                if '<tr><td>ResponseAuthKey#></td><td>' in line:
                    responsekey = line.replace(
                        ' <tr><td>ResponseAuthKey#></td><td>', '').replace('</td><td></td></tr>', '')
                    responsekey = responsekey.strip()
                    logger.info('Got CIMC Shell ResponseAuthKey', responsekey)
                    self.execute_cmd_serial(responsekey)

                    time.sleep(2)
                    self.execute_cmd_serial('stty cols 110')
                    self.execute_cmd_serial('stty rows 50')
                    self.execute_cmd_serial('stty sane')
        elif sldp_enabled == 'yes':
            logger.info('SLDP is enabled')
            output = self.execute_cmd_serial('sldp')
            logger.info('sldp output:')
            logger.info(output)
            if 'login:' in output:
                logger.info('Entering the User name')
                self.execute_cmd_serial('admin')
                logger.info('Entering the Passed')
                output = self.execute_cmd_serial('Topspin515')
            challenge_key = re.search('Challenge[ \t]+.*\W+(.*\W+.*\W+.*)\W+', output).group(1)
            logger.info('Challenge Key:' + str(challenge_key))
            response_key = self.get_challenge_response_string(challenge_key)
            self.execute_cmd_serial(response_key)
        logger.info('Successfully logged into DFU shell')

    def get_challenge_response_string(self, challenge_key, ticket_dir=None, debug=1):
        cid_obj = cid.cid_ret('10', 'Testing Message', True)
        cid_obj.cid_print('Getting the Challenge key using SLDP authentication')
        if ticket_dir != None:
            ticket_dir = ticket_dir
        else:
            ticket_dir = '/data/home/jchanda/cid/tickets'
        # ticket_dir = ['/data/home/jchanda/cid/tickets' if ticket_dir == None else
        #              '/data/home/jchanda/cid/tickets']
        debug = 1
        logger.info('TICKET DIR: ' + str(ticket_dir))
        response_key = cid_obj.get_response_string(challenge_key, ticket_dir, debug)
        logger.info('Response String:')
        logger.info(response_key)
        # response_key = re.search('Response\[ \t]+.*\W+((?:.*\W){11})', response).group(1).strip()
        return response_key

    def connect_to_host_efi(self, post_flag=False):
        try:
            telnet_handle = telnetlib.Telnet(
                self.ip.encode('ascii'),
                self.host_port)
            telnet_handle.set_debuglevel(10)
            self.host_conn_handle = telnet_handle
            self.host_conn_handle.write(b'\n')

        except:
            dump_error_in_lib()

            tem_handle = self.connect_to_terminal_srvr()
            # Have to handle the server_Type here
            if self.server_type == None or 'cisco' in self.server_type:
                i = 0
                while i < 4:
                    tem_handle.write(b'clear line ' +
                                     str(self.host_port)[2:].encode('ascii') +
                                     b'\n')
                    tem_handle.read_until(b'[confirm]', 5).decode('ascii')
                    tem_handle.write(b'\n')
                    i += 1
                    time.sleep(3)

            try:
                telnet_handle = telnetlib.Telnet(
                    self.ip.encode('ascii'),
                    self.host_port)
                telnet_handle.set_debuglevel(10)
                self.host_conn_handle = telnet_handle
                self.host_conn_handle.write(b'\n')

            except:
                dump_error_in_lib()
                return None

        host_handle = self.host_conn_handle
        host_handle.write(b'\r\n')
        output = ''
        post_data = ''
        if post_flag:
            post_data = host_handle.read_until(b'Mhz', 300).decode('ascii')
            logger.info("""output during BIOS post""")
            logger.info(output)
            time.sleep(120)

        try:
            logger.info('Terminating existing session')
            print('booted to EFI shell 1 try block')

            try:
                output += host_handle.read_until(b'Shell>', 5).decode('ascii')
                logger.info("""output""")
                logger.info(output)
                i = 0
                while i < 30:
                    print('in while')
                    if 'Shell>' in output:
                        time.sleep(5)
                        logger.info('Booted into EFI shell')
                        break
                    else:
                        time.sleep(10)
                        print('waiting for boot into efi shell')
                        host_handle.write(b'\n\r')
                        try:
                            output += host_handle.read_until(
                                b'Shell>',
                                5).decode('ascii')
                        except:
                            print('do nothing1')
                    i += 1
                    host_handle.write(b'\r\n')
            except:
                print('do nothing')

        except:
            dump_error_in_lib()

            tem_handle = self.connect_to_terminal_srvr()
            # Have to handle the server_Type here
            if self.server_type is None:
                i = 0
                while i < 4:
                    tem_handle.write(b'clear line ' +
                                     str(self.host_port)[2:].encode('ascii') +
                                     b'\n')
                    tem_handle.read_until(b'[confirm]', 5).decode('ascii')
                    tem_handle.write(b'\n')
                    i += 1
            try:
                logger.info('Terminating existing session')
                logger.info(host_handle.read_until(b'Shell>', 5))
                print('booted to EFI shell second try block')
                host_handle.write(b'\r\n')
                logger.info(host_handle.read_lazy())

            except:
                dump_error_in_lib()
                return None
        if post_flag:
            return (host_handle, post_data)
        else:
            return host_handle

    def check_file_on_console_host(self, command):
        '''Procedure to verify the dummy file using host console'''
        logger.info(
            'Validate dummy file {} created on booted host OS'.format(command))
        found_file = False
        out = self.execute_cmd_serial_host(command)
        logger.info('Expected string Command output')
        logger.info(out)
        logger.info('Encoded string')
        logger.info(out.encode('ascii'))
        if 'No such file or directory' in out or 'File not found' in out:
            logger.warning('Failed to verify dummy {} file found on host'.
                           format(command).split()[1])
        else:
            logger.info('Expected file {} found on the remote host'.format(command).split()[1])
            found_file = True

        if found_file is True:
            logger.info('Successfully validated the expected file {} found \
                in console output'.format(command).split()[1])
            return True
        else:
            logger.error('Failed to validate that expected file {} found \
                in console output'.format(command).split()[1])
            return False

    def validate_host_console_output(self, exp_string, wait_time=500):
        '''Procedure to verify the expected string on host console output during boot'''
        logger.info('Looking for the console output {}'.format(exp_string))
        try:
            out = self.host_conn_handle.read_until(exp_string, wait_time)
            logger.info('Host console output:')
            logger.info(out)
            found_string = False
            for line in out.splitlines():
                logger.info(line)
                if exp_string in line:
                    logger.info('Found expected string')
                    found_string = True
                    break
            if exp_string in out:
                found_string = True
            if found_string is True:
                logger.info('Successfully validated the expected string {} found \
                    in console output'.format(exp_string))
                return True
            else:
                logger.error('Failed to validate that expected string {} found \
                    in console output'.format(exp_string))
                return False
        except:
            dump_error_in_lib()
            logger.error(
                'Failed to validate console output with expected string {}'.format(exp_string))
            return False

    def enter_power_on_password(self, exp_string, pop=b'cisco123', wait_time=500):
        '''Procedure to enter the BIOS security Power On Password through the host console output during boot'''
        logger.info('Looking for the Power on Password expected string on console output {}'.format(exp_string))
        logger.info('Power on password from config file: ' + str(pop))
        try:
            out = self.host_conn_handle.read_until(exp_string, wait_time)
            logger.info('Host console output:')
            logger.info(out)
            found_string = False
            for line in out.splitlines():
                logger.info(line)
                if exp_string in line:
                    logger.info('Found expected string')
                    found_string = True
                    break
            if exp_string in out:
                found_string = True
            if found_string is True:
                logger.info('Successfully validated the expected string {} found \
                    in console output'.format(exp_string))
                self.host_conn_handle.write(pop)
                self.host_conn_handle.write(b'\r\n')
                return True
            else:
                logger.error('Failed to validate that expected string {} found \
                    in console output'.format(exp_string))
                return False
        except:
            dump_error_in_lib()
            logger.error(
                'Failed to validate console output with expected string {}'.format(exp_string))
            return False

    def get_post_out(self, read_data=b'Mhz'):
        try:
            telnet_handle = telnetlib.Telnet(
                self.ip.encode('ascii'),
                self.host_port)
            telnet_handle.set_debuglevel(10)
            self.host_conn_handle = telnet_handle
            self.host_conn_handle.write(b'\n')

        except:
            dump_error_in_lib()

            tem_handle = self.connect_to_terminal_srvr()
            # Have to handle the server_Type here
            if self.server_type is None:
                i = 0
                while i < 4:
                    tem_handle.write(b'clear line ' +
                                     str(self.host_port)[2:].encode('ascii') +
                                     b'\n')
                    tem_handle.read_until(b'[confirm]', 5).decode('ascii')
                    tem_handle.write(b'\n')
                    i += 1
                    time.sleep(3)

            try:
                telnet_handle = telnetlib.Telnet(
                    self.ip.encode('ascii'),
                    self.host_port)
                telnet_handle.set_debuglevel(10)
                self.host_conn_handle = telnet_handle
                self.host_conn_handle.write(b'\n')

            except:
                dump_error_in_lib()
                return None

        host_handle = self.host_conn_handle
        host_handle.write(b'\r\n')
        post_data = host_handle.read_until(read_data, 500)
        logger.info("""output during BIOS post""")
        logger.info(post_data)
        self.disconnect()
        return post_data

    def configure_cimc_network_params(self, config):
        '''
        Procedure to configure the static CIMC network parameters
        '''
        mgmt_detail_obj = config.mgmtdetail
        bmc_ip = mgmt_detail_obj.bmc_mgmt_ip
        bmc_name = mgmt_detail_obj.bmc_prompt
        net_mask = mgmt_detail_obj.bmc_net_mask
        gway = mgmt_detail_obj.bmc_gway
        # common values across all testbeds
        preffered_dns = '171.70.168.183'
        alternate_dns = '171.68.226.120'
        mode = 'dedicated'
        redundancy = 'none'

        self.execute_cmd_serial('top')
        self.execute_cmd_serial('scope cimc')
        self.execute_cmd_serial('scope network')
        self.execute_cmd_serial('set v4-addr ' + bmc_ip)
        self.execute_cmd_serial('set dhcp-enabled no')
        self.execute_cmd_serial('set dns-use-dhcp no')
        self.execute_cmd_serial('set ddns-enabled no')
        self.execute_cmd_serial('set v4-netmask ' + net_mask)
        self.execute_cmd_serial('set v4-gateway ' + gway)
        self.execute_cmd_serial('set preferred-dns-server ' + preffered_dns)
        self.execute_cmd_serial('set alternate-dns-server ' + alternate_dns)
        self.execute_cmd_serial('set mode ' + mode)
        self.execute_cmd_serial('set redundancy ' + redundancy)
        out = self.execute_cmd_serial('set hostname ' + bmc_name)
        if 'Create new certificate' in out:
            self.execute_cmd_serial('y')
        commit_out = self.execute_cmd_serial('commit', 5)
        if 'Do you wish to continue' in commit_out:
            out = self.execute_cmd_serial('y', 20)
            try:
                if 'Killed' in out:
                    logger.info('Successfully applied all network settings')
                    return True
            except:
                logger.warning('Ignore.')
                return True
        else:
            logger.error('Failed to apply the network settings parameter. Error msg: %s' % (commit_out))
            return False

    def factory_reset(self, comp=None):
        '''
        Procedure to perform BMC factory reset

        returns:    True: on Success
                    False: on Failure
        '''
        self.execute_cmd_serial('top')
        self.execute_cmd_serial('scope chassis')
        if comp is None:
            comp = 'bmc'
        out = self.execute_cmd_serial('factory-default ' + comp)
        if 'Continue' in out:
            out = self.execute_cmd_serial('y')
            if 'started' in out:
                logger.info('factory-default for %s started successfully' % (comp))
                return True
            else:
                logger.error('Failed: to perform factory-default of %s, got Output as %s' % (comp, out))
                return False
        else:
            logger.error('Failed: to perform factory-default of %s, got Output as %s' % (comp, out))
            return False

    def bmc_serial_recover_testbed(self, config, comp=None, wait_time=None):
        '''
        Recovers a testbed. It connects the bmc serial console.
        it then set the BMC to a factory default, restores
        and verifies the network.
        '''
        logger.info('Performing bmc factory reset and recovers the testbed')

        # serial connect to bmc
        self.connect_to_mgmnt()

        # change the mode to CLI mode
        prompt = 'cliMode'
        if self.set_bmc_serial_mode(prompt) is False:
            logger.error('Failed: unable to change CIMC serial console to CLI mode')
            return False
        else:
            logger.info('CIMC serial console already in CLI mode')

        # Perform CIMC Factory Reset
        if self.factory_reset() is False:
            return False

        # Read until '[ help ]#' prompt after the factory reset
        if wait_time is not None:
            wt_time = wait_time
        else:
            wt_time = 300
        help_prompt = b'[ help ]#'
        out = self.mgmnt_conn_handle.read_until(help_prompt, wt_time)
        logger.info('BMC serial console output after factory reset:')
        logger.info(out)

        # serial connect to BMC again
        logger.info('Connecting back to bmc serial console again')
        self.connect_to_mgmnt()

        # Change the mode to CLI mode
        if self.set_bmc_serial_mode(prompt) is False:
            logger.error('Failed: unable to change CIMC serial console to CLI mode after factory reset')
            return False
        else:
            logger.info('CIMC serial console is in CLI mode after factory reset')

        # configure all network parameters
        if self.configure_cimc_network_params(config) is False:
            return False

        logger.info('Successfully recovred the CIMC after Factory Reset.')
        return True
