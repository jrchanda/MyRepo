'''
__author__ = 'Jagadish Chanda <jchanda@cisco.com>'
__copyright__ = 'Copyright 2017, Cisco Systems'
__email__ = 'jchanda@cisco.com'
__date__ = 'Sept 13,2017'
__version__ = 1.0
'''
# Needed for aetest script
import logging
import time
import re
from collections import defaultdict
from ats import aetest

from common_utils import dump_error_in_lib, get_host_mgmt_ip
from linux_utils import LinuxUtils
from common_test import Setup, Cleanup
from processor_lib import ProcessorUtils
from host_utils import HostUtils
from bios_utils import BiosUtils
from boot_order import BootOrder
import common_utils

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
    def initial_setup(self, cimc_util_obj, config):
        '''
        Initial Setups
        '''
        global classparam
        classparam['bios_obj'] = cimc_util_obj.bios_util_obj
        classparam['host_utils'] = HostUtils()
        classparam['host_ip'] = get_host_mgmt_ip(config)

################# Common setup Ends ##############################################


################# Start of Testcase - verifyProcessorDetails #####################
class VerifyBiosTokensTest(aetest.Testcase):
    '''
        Verify BIOS Tokens After CMOS Clear, Load defaults and Load Mfg defaults
        1. Clear BIOS CMOS, and validate the tokens
        2. Set default values for BIOS setup parameters, and validate the tokens
        3. Reset BIOS setup parameters to manufacturing defaults, and validate the tokens
    '''
    @aetest.setup
    def setup(self, cimc_util_obj, non_default_tokens=None):
        '''
        Test Case Setup
        '''
        log.info("Setup Section verifyProcessorDetails")
        bios_obj = classparam['bios_obj']
        host_util = classparam['host_utils']

        # create json profile and copy to remote tftp share
        if bios_obj.create_bios_profile_and_copy2tftpshare(non_default_tokens) is False:
            self.failed('Failed to create bios json file on remote tftp share', goto['cleanup'])
        else:
            log.info('Successfully created and copied json format file to tftp share')

    bios_default_options = ['bios-setup-default', 'clear-cmos', 'restore-mfg-defaults']

    @aetest.test.loop(uids=['load_bios_default_test', 'cmos_clear_test', 'restore_mfg_defaults_test'],
                      parameter=bios_default_options)
    def test(self, cimc_util_obj, config, parameter, non_default_tokens):
        '''
        Test Case Test Section
        '''
        bios_obj = classparam['bios_obj']
        host_util = classparam['host_utils']
        host_ip = classparam['host_ip']

        log.info('Changing some of the tokens to non default values')
        if parameter == 'restore-mfg-defaults':
            if non_default_tokens is not None:
                user_token_dict = non_default_tokens
            else:
                user_token_dict = {'PwrPerfTuning': 'BIOS',
                                   'IntelVT': 'Disabled',
                                   'FRB-2': 'Disabled',
                                   'CoherencySupport': 'Enabled',
                                   'TPMControl': 'Disabled',
                                   'ATS': 'Disabled',
                                   'AdjacentCacheLinePrefetch': 'Disabled'
                                   }
            res = bios_obj.load_bios_mfg_custom_tokens(user_token_dict)
            if res is False:
                self.failed('Failed to load mfg bios tokens', goto=['cleanup'])
        else:
            # install and activate the bios profile on CIMC
            res = bios_obj.install_and_activate_bios_profile(reboot='yes')
            if res is True:
                log.info('Bios profile activation successful. Wait for host to come up')
                # Wait for host to reboot
                res = cimc_util_obj.verify_host_up(host_ip, wait_for_ping_fail=False)
                if res is False:
                    log.warning('Failed to ping the host after host reboot')
                    self.failed('Failed to ping host', goto=['cleanup'])

        log.info('Performing BIOS Operation: ' + str(parameter))
        res = bios_obj.restore_tokens_to_defaults(parameter)
        if res == False:
            self.failed('Failed to perform %s operation' % (parameter))
        else:
            log.info('Successfully performed %s operation' % (parameter))

        bios_scope_list = ['input-output', 'memory', 'power-or-performance', 'processor', 'security', 'server-management']
        scope_name_dict = {'input-output': 'input_output',
                           'memory': 'memory',
                           'power-or-performance': 'power_or_performance',
                           'processor': 'processor',
                           'security': 'security',
                           'server-management': 'server_management'
                           }
        result = None
        for bios_scope in bios_scope_list:
            bios_dict = {}
            cimc_util_obj.handle.execute_cmd_list('top', 'scope bios', 'scope ' + bios_scope)
            scope_out = cimc_util_obj.handle.execute_cmd('show detail')
            log.info('Output of bios scope {} are:'.format(bios_scope))
            log.info(scope_out)
            for line in scope_out.split('\n'):
                if line == '---' or line == '...' or not line:
                    continue
                try:
                    tup = re.search('([^\s].+):\s+([^\r\n]+)', line).groups()
                    # exception token, not adding to dict
                    if tup[0] == 'CPUPerformance':
                        continue
                    bios_dict[tup[0]] = '_'.join(tup[1].split(' '))
                except Exception as e:
                    log.info('Exception: ' + str(e))
            log.info('Dictionary values' + str(bios_dict))
            if parameter == 'restore-mfg-defaults':
                out = bios_obj.validate_mfg_custom_default_tokens(bios_dict, user_token_dict, scope_name_dict[bios_scope])
            else:
                out = bios_obj.validate_default_tokens(bios_dict, scope_name_dict[bios_scope])
            if out is False:
                log.info('{} scope bios tokens are failed to match with expected default tokens'.format(bios_scope))
                result = 'Failed'
            else:
                log.info('{} scope bios tokens are validated successfully'.format(bios_scope))

        if result == 'Failed':
            self.failed('Failed to validate BIOS tokens after CMOS clear')
        else:
            self.passed('Successfully validated the tokens after CMOS clear')

    @aetest.cleanup
    def cleanup(self):
        '''
        Test Case Cleanup
        '''
        log.info('Cleanup section passed')

