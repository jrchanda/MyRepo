'''
__author__ = 'Jagadish Chanda <jchanda@cisco.com>'
__copyright__ = 'Copyright 2017, Cisco Systems'
__email__ = 'jchanda@cisco.com'
__date__ = 'Oct 13,2017'
__version__ = 1.0
'''
# Needed for aetest script
import logging
import subprocess

from ats import aetest

from common_utils import dump_error_in_lib, get_host_mgmt_ip
from common_test import Setup, Cleanup
import common_utils
import host_utils


################################################################################
# Global class variable to maintain objects by creating one time and
# use all over the script
################################################################################
classparam = {}

# Get your logger for your script
log = logging.getLogger(__name__)

################# Common setup Starts ############################################


class CommonSetup(Setup):
    '''
    Common Setup
    '''
    @aetest.subsection
    def connect(self, testscript, testbed_name):
        '''
        creates mandatory objects
        '''
        super(CommonSetup, self).connect(testscript, testbed_name)

    @aetest.subsection
    def initial_setup(self, cimc_util_obj, config, con_obj):
        '''
        Initial Setups
        '''
        global classparam
        host_ip = common_utils.get_host_mgmt_ip(config)
        print('%%%%%%%%%%%%%%%%%%%%%%%%')
        print(host_ip)
        print('%%%%%%%%%%%%%%%%%%%%%%%%')

        host_ip3 = config.host_info[0].nw_intf_list[0].ip_address
        print('===============')
        print(host_ip3)
        print('===============')

        exit()
        classparam['host_ip'] = get_host_mgmt_ip(config)
        ####classparam['bmc_serial_handle'] = cimc_util_obj.telnet_handle

        mgmt_detail_obj = config.mgmtdetail
        classparam['bmc_ip'] = mgmt_detail_obj.bmc_mgmt_ip
        classparam['bmc_login'] = mgmt_detail_obj.bmc_login
        classparam['bmc_passwd'] = mgmt_detail_obj.bmc_password

################# Common setup Ends ##############################################


################# Start of Testcase - verifyProcessorDetails #####################
class FactoryResetTest(aetest.Testcase):
    '''
    Configure boot device to boot to bios, pxe, hdd, cdrom, floppy in non-persistent mode using IPMI
    '''
    @aetest.setup
    def setup(self):
        '''
        Test Case Setup
        '''
        log.info("Setup Section FactoryResetTest")

    @aetest.test
    def test(self, cimc_util_obj):
        log.info("Test Section FactoryResetTest")
        res = cimc_util_obj.bmc_factory_reset_and_connect()
        if res is True:
            self.passed('Test Passed')
        else:
            self.failed('Test Failed')

    @aetest.cleanup
    def cleanup(self):
        '''
        Test Case Cleanup
        '''
        # disconnect host serial handle
        log.info('Cleanup section passed')
