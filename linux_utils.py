import logging
import re
import socket
import time
import paramiko
import requests

from common_utils import dump_error_in_lib

logger = logging.getLogger(__name__)

__author__ = 'Balamurugan Ramu <balramu@cisco.com>'
__copyright__ = 'Copyright 2016, Cisco Systems'
__email__ = 'balramu@cisco.com'
__date__ = 'Sep 20,2016'
__version__ = 1.0


class LinuxUtils():
    '''
     Utility on top of paramiko library for interacting with  linux hosts and
     remote management tools of Cisco C- Series
    server using SSH .
    '''

    def __init__(self, ip, username, password):
        self.ip = ip
        self.username = username
        self.password = password
        self.handle = None
        logger.info("SSH handle created successfully")

    def connect(self):
        '''
           Connects to the host with given credentials and saves the handle in
           the current object

        '''
        try:
            remote_conn_pre = paramiko.SSHClient()
            # Automatically add untrusted hosts (make sure okay for security
            # policy in your environment)
            remote_conn_pre.set_missing_host_key_policy(
                paramiko.AutoAddPolicy())
            # initiate SSH connection
            remote_conn_pre.connect(self.ip, username=self.username,
                                    password=self.password,
                                    look_for_keys=False, allow_agent=False)
            self.handle = remote_conn_pre.invoke_shell()
            self.handle.keepthis = remote_conn_pre
            logger.info("Successfully connected to the host with IP:" +
                        self.ip +
                        " username:" + self.username + " password:" + self.password)
            self.execute_cmd("set cli output yaml")
            self.handle.settimeout(10)
        except:
            dump_error_in_lib()
            return False

    def execute_cmd(
            self, cmds, buffer_size=50000, encode='utf_8', wait_time=4):
        '''
        Executes the command passed prerequiste is that connect method has to be
        called before
        '''
        output = ''
        try:
            '''
            self.handle.send('\n')
            output = self.handle.recv(buffer_size).decode(encoding='utf_8', errors='strict')
            output = ''
            '''
            self.handle.send(cmds + "\n")
            logger.info("Executed cmd: " + cmds + " successfully")
            time.sleep(wait_time)
            if encode is 'utf_8':
                output = self.handle.recv(buffer_size).decode(
                    encoding='utf_8',
                    errors='strict')
            else:
                output = self.handle.recv(buffer_size)
            logger.info("output of the executed command is :" + str(output))
        except OSError:
            dump_error_in_lib()
            logger.info('In execption block of execute_cmd')
            self.connect()
            time.sleep(2)
            self.handle.send(cmds + "\n")
            time.sleep(wait_time)
            logger.info("Executed cmd: " + cmds + " successfully")
            if encode is 'utf_8':
                output = self.handle.recv(buffer_size).decode(
                    encoding='utf_8',
                    errors='strict')
            else:
                output = self.handle.recv(buffer_size)
            logger.info("output of the executed command is :" + str(output))
        return output

    def execute_cmd_list(self, *cmd_list, buffer_size=50000, wait_time=4):
        '''
        Executes the list of command passed one by one
        '''

        try:
            output = ''
            for cmd in cmd_list:
                tempoutput = self.execute_cmd(cmd, buffer_size)
                output += tempoutput
                while '--More--' in tempoutput:
                    tempoutput = self.execute_cmd('r')
                    output += tempoutput
            time.sleep(wait_time)
            output += self.handle.recv(buffer_size).decode(
                encoding='utf_8',
                errors='strict')
        except socket.timeout:
            logger.info('socket timeout in execute command list')
        return output

    def connect_debug_shell(self):
        '''
        Connects to Cisco IMC debug shell from the BMC / CMC ssh connection
        '''
        self.execute_cmd("connect debug-shell")
        output = self.execute_cmd("load debug plugin")
        data = ''
        responsekey = ''
        response_data = None
        key_gen_uri = 'http://savbu-swbmc-vbld1.cisco.com/CIMC-key/generate?key='
        line_list = re.split("\r\n", output)
        for line in line_list:
            if 'ChallengeKey#>' in line:
                data = line.replace('ChallengeKey#> ', '')
                response_data = requests.get(key_gen_uri + data)
        key_output = response_data.text.split('\n')
        for line in key_output:
            if '<tr><td>ResponseAuthKey#></td><td>' in line:
                responsekey = line.replace(' <tr><td>ResponseAuthKey#></td><td>',
                                           '').replace('</td><td></td></tr>', '')
                responsekey = responsekey.strip()
                self.execute_cmd(responsekey)

    def disconnect(self):
        '''
        close the connection handle
        '''
        self.handle.close()

    def copy_local_to_remote(self, local_path, remote_path):
        '''
        Copy a local file to a remote location
        Prerequisites:
            Need to connect remote host before calling this procedure.
        local_path : full path to file on local execution system
        remote_path : full path to file on remote system
        '''
        try:
            sftp = self.handle.keepthis.open_sftp()
            logger.info('Opened sftp connection to remote host')
            sftp.put(local_path, remote_path)
            logger.info(
                'Copied local file {} on remote host'.format(local_path))
            sftp.close()
            return True
        except:
            dump_error_in_lib()
            return False

    def copy_remote_to_local(self, remote_path, local_path):
        '''
        Copy a local file to a remote location
        Prerequisites:
            Need to connect remote host before calling this procedure.
        remote_path : full path to file on remote system
        local_path : full path to file on local execution system
        '''
        try:
            sftp = self.handle.keepthis.open_sftp()
            logger.info('Opened sftp connection to remote host')
            sftp.get(remote_path, local_path)
            logger.info(
                'Copied remote file {} on local host {}'.format(
                    remote_path,
                    local_path))
            sftp.close()
            return True
        except:
            dump_error_in_lib()
            return False
