# Needed for aetest script
import logging
from ats import aetest
# Needed for aetest script
import logging
import os
from ats import aetest
from ats import easypy
from config_parser import ConfigParser
from linux_utils import LinuxUtils
from telnet_utils import TelnetUtil
from common_test import Setup, Cleanup
from cimc_utils import CimcUtils
from processor_lib import ProcessorUtils
import re
from logging.config import thread
import time
import cimc_utils
from difflib import restore
from host_utils import HostUtils
# Get your logger for your script
logger = logging.getLogger(__name__)

classparam = {'bios_config': '', 'procc_obj': '', 'host_utils': ''}


class CommonSetup(Setup):

    @aetest.subsection
    def connect(self, testscript, testbed_name):
        super(CommonSetup, self).connect(testscript, testbed_name)

    @aetest.subsection
    def initial_setup(self, cimc_util_obj, config):
        global classparam
        classparam['bios_obj'] = cimc_util_obj.bios_util_obj
        #plat_type = config.mgmtdetail.platform_series


################# Common setup Ends ##############################################

################# Start of Testcase - ConsoleRedirection #####################

class ConsoleRedirection (aetest.Testcase):

    @aetest.test
    def setup(self, cimc_util_obj, config):
        logger.info("Setup ConsoleRedirection")
        out = classparam['bios_obj'].console_redirect_defaults()
        if out is False:
            self.failed("Failed to set default console redirection")

        sol_enabled = classparam['bios_obj'].get_common_token_value("enabled", "sol")
        logger.info("Sol enabled value is" + sol_enabled)
        if 'yes' in sol_enabled:
            status = classparam['bios_obj'].set_common_token_value("enabled", "no", "sol", commit_wait=120)
            if status is False:
                logger.error("Failed to set sol enabled to no")
                self.failed("Failed to set sol enabled to no")
    '''
        #######################################################
        Test Case : verify_console_redirection
        Logical ID :
        RACK-BIOS-DN-Console Redirection-001
        RACK-BIOS-DN-Console Redirection-002
        RACK-BIOS-DN-Console Redirection-003
        RACK-BIOS-DN-Console Redirection-004
        RACK-BIOS-DN-Console Redirection-005
        RACK-BIOS-DN-Console Redirection-006
        RACK-BIOS-DN-Console Redirection-007
        RACK-BIOS-DN-Console Redirection-008
        RACK-BIOS-DN-Console Redirection-011
        RACK-BIOS-DN-Console Redirection-012
        RACK-BIOS-DN-Console Redirection-013
        #######################################################
    '''
    if 'M5' in os.environ["PLATFORM_SER"]:
        param = [['FlowCtrl', 'None'], ['FlowCtrl', 'RTS-CTS'], ['BaudRate', '115.2k'],
                 ['TerminalType', 'PC-ANSI'], ['TerminalType', 'VT100'], ['TerminalType', 'VT100-PLUS']]
        ids = ['FlowCtrl_None', 'FlowCtrl_RTS/CTS', 'BaudRate_115200', 'TerminalType_PC_ANSI', 'TerminalType_VT100', 'TerminalType_VT100+']
    else:
        param = [['FlowCtrl', 'None'], ['FlowCtrl', 'Hardware_RTS/CTS'], ['BaudRate', '115200'], ['TerminalType', 'PC-ANSI'],
                 ['TerminalType', 'VT100'], ['TerminalType', 'VT100+'], ['comSpcrEnable', 'Enabled'], ['comSpcrEnable', 'Disabled']]
        ids = ['FlowCtrl_None', 'FlowCtrl_RTS/CTS', 'BaudRate_115200', 'TerminalType_PC_ANSI',
               'TerminalType_VT100', 'TerminalType_VT100+', 'Out_of_bound_enabled', 'Out_of_bound_disabled']

    @aetest.test.loop(uids=ids, parameter=param)
    def verify_console_redirection(self, cimc_util_obj, config, parameter):
        # Creating Bios Config
        bios_obj = classparam['bios_obj']
        telnet_handle = cimc_util_obj.telnet_handle
        results = 'Pass'
        token = parameter[0]
        value = parameter[1]
        token_value = bios_obj.get_bios_token_value(token)
        if value not in token_value:
            if bios_obj.set_bios_token_value(token, value, 'advanced', commit_wait=150) is False:
                self.failed("Failed to set Token " + token + " to " + value)
        if cimc_util_obj.set_host_power("off") is False:
            self.failed("Failed to power off host")
        elif cimc_util_obj.set_host_power("on") is False:
            self.failed("Failed to power on host")
        #logger.info("Setting Token "+token+" to "+value+" Successfully")
        host_ser = telnet_handle.get_post_out().decode('utf-8')
        #host_ser = re.sub('[^A-Za-z0-9]+', '', host_ser)
        if host_ser is None:
            self.failed("Failed to connect to host through serial")
        else:
            logger.info(host_ser)
            if 'Cisco Systems' in host_ser:
                results = 'Pass'
            else:
                results = 'Fail'
        if results == 'Fail':
            self.failed("Console redirection verification for " + token + " with value " + value + " Failed")
        else:
            self.passed("Console redirection verification for " + token + " with value " + value + " verified successfully")

    #########################################################################################
    '''
            #######################################################
            Test Case : verify_sol
            Logical ID :
            RACK-BIOS-DN-Console Redirection-009
            RACK-BIOS-DN-Console Redirection-010
            ######################################################
    '''
    if 'M5' in os.environ["PLATFORM_SER"]:
        sol_param = [['BaudRate', '9.6k'], ['BaudRate', '115.2k']]
        ids1 = ['sol_verify_baudrate_9.6k', 'sol_verify_baudrate_115.2k']
    else:
        sol_param = [['BaudRate', '9600'], ['BaudRate', '115200']]
        ids1 = ['sol_verify_baudrate_9.6k', 'sol_verify_baudrate_115.2k']

    @aetest.test.loop(uids=ids1, parameter=sol_param)
    def verify_sol(self, cimc_util_obj, config, parameter):
        token = parameter[0]
        value = parameter[1]
        logger.info("token " + token)
        bios_obj = classparam['bios_obj']
        token_value = bios_obj.get_bios_token_value(token)
        logger.info(token + "value is " + token_value)
        if value not in token_value:
            if bios_obj.set_bios_token_value(token, value, 'advanced', commit_wait=150) is False:
                self.failed("Failed to set Token " + token + " to " + value)
        if cimc_util_obj.verfiy_sol_screen(config) is True:
            self.passed("Successfully verified sol after setting baudrate to" + value)
        else:
            self.failed("Failed to verify sol after setting baudrate to " + value)


class CommonCleanUp(Cleanup):

    @aetest.subsection
    def cleanup(self, mgmt_handle):
        super(CommonCleanUp, self).clean_everything(mgmt_handle)
