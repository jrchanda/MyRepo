#!/usr/bin/env python
'''
ApcPowerControl.py

Class to connect to a APC and perform power operation

Parameters:
ApcIP  : APC IP address or hostname
APCUser: Username to use for connection
APCPass: Password for connection

Assumption: SSH service is enabled on remote system

Requirement: pexpect package
'''
from __future__ import print_function
from builtins import str
from builtins import object
import pexpect
import logging
import re
from linux_utils import LinuxUtils

logger = logging.getLogger(__name__)

__author__ = 'Pratap Keshava <prkeshav@cisco.com>'
__copyright__ = 'Copyright 2016, Cisco Systems'
__email__ = 'prkeshav@cisco.com'
__date__ = 'Feb 16, 2016'
__version__ = 1.0


class APCUtilClass(object):

    def __init__(self, ApcIP, APCUser, APCPass):
        '''
        Contructor for the class

        Parameters:
        ApcIP  : APC IP address or hostname
        APCUser: Username to use for connection
        APCPass: Password for connection

        client : handle for connection
        prompt : Need to update to handle different cases
        '''
        self.ApcIP = ApcIP
        self.APCUser = APCUser
        self.APCPass = APCPass
        self.client = None
        self.prompt = '>'

    def ConnectToAPC(self):
        '''
        Connect to APC using interactive shell
        The procedure uses SSH to connect to APC

        Basic error handling
        '''
        try:
            cmd = '/usr/bin/ssh -oUserKnownHostsFile=/dev/null -oStrictHostKeyChecking=no '
            cmd += self.APCUser
            cmd += '@'
            cmd += self.ApcIP
            logger.info('Command : %s ' % cmd)
            self.client = pexpect.spawn(cmd)
            self.client.expect('password')
            self.client.sendline(self.APCPass)
            self.client.expect(self.prompt)
            return(self.client)
        except Exception as inst:
            logger.info('Caught exception while connecting to APC %s ' % self.ApcIP)
            logger.info(type(inst))
            logger.info(inst.args)
            logger.info(inst)
            return(None)

    def DisnnectFromAPC(self):
        '''
        Disnnect From APC
        Close the Connection handle after operations are done

        Basic error handling
        '''
        try:
            self.client.sendline("exit")
            return(0)
        except Exception as inst:
            logger.info('Caught exception while connecting to APC %s ' % self.ApcIP)
            logger.info(type(inst))
            logger.info(inst.args)
            logger.info(inst)
            return(None)

    def GetPowerStatePort(self, portNum):
        '''
        Get Power status for APC port
        Uses the port number passed to procedure and returns the current status

        Input   : Port number to which server is connected

        Returns : on/off in case of success
                : None in case of Failure

        Assumption: user passes the appropriate port number
        Basic error checking
        '''
        try:
            command = "show outlets "
            command += str(portNum)
            self.client.sendline(command)
            self.client.expect(self.prompt)
            output = self.client.before
            logger.info('output: ' + output.decode('ascii'))
            match = re.search("Power state:[ ]+([^\r\n]+)", output.decode('ascii'))
            power_state = None
            if match != None:
                power_state = match.group(1)
            else:
                power_state = None
            return(power_state)

        except Exception as inst:
            logger.info('Caught exception while executing command %s ' % command)
            logger.info(type(inst))
            logger.info(inst.args)
            logger.info(inst)

    def SetPowerStatePort(self, portNum, operation):
        '''
        Set Power status for APC port
        Set the port state to on or off depending on need
        Input   : on for powering on a port
                : off for powering off a port
                : (other values will be rejected)

        Returns : 1 in case of success
                : None in case of failure

        Assumption: user passes the appropriate port number
        Basic error checking
        '''
        try:
            if operation == "on" or operation == "off":
                logger.info('Valid Value passed for operation')
            else:
                logger.info('Please pass valid value on/off for operation')
                return(None)
            command = "power outlets "
            command += str(portNum)
            command += " "
            command += operation
            self.client.sendline(command)
            self.client.expect('y/n]')
            self.client.sendline('y')
            self.client.expect(self.prompt)
            output = self.client.before
            logger.info('output: ' + output.decode('ascii'))
            return(1)

        except Exception as inst:
            logger.info('Caught exception while executing command %s ' % command)
            logger.info(type(inst))
            logger.info(inst.args)
            logger.info(inst)
            return(None)

    def apc_cycle_and_reconnect(self, config):
        con = APCUtilClass("10.127.51.191", "apc1", "nbv12345")
        ret = con.ConnectToAPC()
        if ret != None:
            logger.info('Successfully connected to APC')
        else:
            logger.error('Failed to connect to APC')
            return False
        portNum = 10
        operation = "off"
        val = con.SetPowerStatePort(portNum, operation)
        if val == None:
            logger.error('Failed to set power state of port number ' + str(portNum) + ' with : ' + operation)
            return False
        else:
            logger.info('Power state of port number ' + str(portNum) + ' set to : ' + operation)
        val = con.GetPowerStatePort(portNum)
        if val == None:
            logger.error('Failed to get power state of port number ' + str(portNum))
        else:
            logger.info('Power state of port number ' + str(portNum) + ' is : ' + val)
        operation = "on"
        val = con.SetPowerStatePort(portNum, operation)
        if val == None:
            logger.error('Failed to set power state of port number ' + str(portNum) + ' with : ' + operation)
            return False
        else:
            logger.info('Power state of port number ' + str(portNum) + ' set to : ' + operation)
        val = con.GetPowerStatePort(portNum)
        if val == None:
            logger.error('Failed to get power state of port number ' + str(portNum))
        else:
            logger.error('Power state of port number ' + str(portNum) + ' is : ' + val)

        ''' reconnecting to mgmt handle '''
        mgmt_detail_obj = config.mgmtdetail
        bmc_ip = mgmt_detail_obj.bmc_mgmt_ip
        bmc_login = mgmt_detail_obj.bmc_login
        bmc_passwd = mgmt_detail_obj.bmc_password

        res = self.cimc_utils_obj.verify_host_up(bmc_ip, wait_time=500)
        if res is not True:
            logger.error('After AC cycle, failed to ping BMC mgmt IP')
            return False
        else:
            logger.info('After AC cycle, able to ping BMC mgmt IP')
        self.handle = LinuxUtils(bmc_ip, bmc_login, bmc_passwd)
        self.handle.connect()
        return True

if __name__ == '__main__':
    con = APCUtilClass("10.127.51.191", "apc1", "nbv12345")
    ret = con.ConnectToAPC()
    logger.info('Return value :' + str(ret))
    print('Return Value : ' + str(ret))
    if ret != None:
        print('Successfully connected to APC')
    else:
        print('Failed to connect to APC')

    portNum = 10
    val = con.GetPowerStatePort(portNum)
    if val == None:
        print('Failed to get power state of port number ' + str(portNum))
    else:
        print('Power state of port number ' + str(portNum) + ' is : ' + val)

    operation = "on"
    val = con.SetPowerStatePort(portNum, operation)
    if val == None:
        print('Failed to set power state of port number ' + str(portNum) + ' with : ' + operation)
    else:
        print('Power state of port number ' + str(portNum) + ' set to : ' + operation)

    val = con.GetPowerStatePort(portNum)
    if val == None:
        print('Failed to get power state of port number ' + str(portNum))
    else:
        print('Power state of port number ' + str(portNum) + ' is : ' + val)

    operation = "off"
    val = con.SetPowerStatePort(portNum, operation)
    if val == None:
        print('Failed to set power state of port number ' + str(portNum) + ' with : ' + operation)
    else:
        print('Power state of port number ' + str(portNum) + ' set to : ' + operation)

    val = con.GetPowerStatePort(portNum)
    if val == None:
        print('Failed to get power state of port number ' + str(portNum))
    else:
        print('Power state of port number ' + str(portNum) + ' is : ' + val)

    operation = "somejunk"
    val = con.SetPowerStatePort(portNum, operation)
    if val == None:
        print('Failed to set power state of port number ' + str(portNum) + ' with : ' + operation)
    else:
        print('Power state of port number ' + str(portNum) + ' set to : ' + operation)

    con.DisnnectFromAPC()
