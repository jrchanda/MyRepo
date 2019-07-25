import logging
import winrm
from common_utils import dump_error_in_lib


__author__ = 'Balamurugan Ramu <balramu@cisco.com>'
__copyright__ = 'Copyright 2016, Cisco Systems'
__email__ = 'balramu@cisco.com'
__date__ = 'Sep 20,2016'
__version__ = 1.0

logger = logging.getLogger(__name__)

class WindowsUtil:
    ''' Utility which uses windows remote management module for interacting with
    remote windows host using WS-Management Protocol (A standard SOAP based
    protocol).Please check ../docs/windows_remote_mgmnt.txt file for more 
    details about one time configuration required in the host.
    '''
    
    def __init__(self, ip_address=None, user_name=None, password=None):
        self.ip_addr = ip_address
        self.user = user_name
        self.password = password
        try:
            self.connection = winrm.Session(self.ip_addr,
                                            auth=(self.user, self.password))
        except: 
            dump_error_in_lib()
    
    def execute_cmd(self, cmd):
        result = None
        try:
            result = self.connection.run_cmd(cmd)
            logger.info("output of the execute command in windows is" + result.__str__())
        except: 
            dump_error_in_lib()
        return result.std_out
