import logging
import re
import os
import subprocess
from ats import aetest

from common_utils import get_host_mgmt_ip
from linux_utils import LinuxUtils
from boot_order import BootOrder
from common_test import Setup, Cleanup
from host_utils import HostUtils
from firmware_utils import FirmwareUtils
from SystemDetailsCollector_lib import SystemDetailsCapture
import common_utils

################################################################################
# Global class variable to maintain objects by creating one time and
# use all over the script
################################################################################
classparam = {}

# Get your logger for your script
log = logging.getLogger(__name__)

def get_bios_backup_version(cimc_util_obj):
    out = cimc_util_obj.handle.execute_cmd_list('top', 'scope bios', 'show detail')
    for line in out.split('\n'):
        match = re.search('bios-backup-version:\s+([^\r\n]+)', out)
        if match is not None:
            bios_backup_version = match.group(1)
    log.info('BIOS backup version is: ' + bios_backup_version)
    return bios_backup_version
        

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
    def initial_setup(self, cimc_util_obj, common_config, config):
        '''
        Initial Setups
        '''
        global classparam
        classparam['firmware_utils'] = FirmwareUtils(cimc_util_obj, common_config, config)
        classparam['bios_obj'] = cimc_util_obj.bios_util_obj
        classparam['system_capture_object'] = SystemDetailsCapture(cimc_util_obj, config)        
        classparam['host_ip'] = common_utils.get_host_mgmt_ip(config)
        
        #sys_image = '/auto/savbu-rack-builds01/firmware-containers/delnorte1/freel_peak_mr2/3.0.2.26/images/CIMC/C220M4-3.0.2.26.zip'
        try:
            bios_image_path = os.environ['BIOS_IMAGE']
            log.info('BIOS Image Path:' + bios_image_path)
        except KeyError:
            self.skipped('SYSTEM IMAGE not provided in the env, please set system image and run',\
                         goto=['CommonCleanup'])
        bios_obj = classparam['bios_obj']
        firmware_utils_obj = classparam['firmware_utils']        
        log.info('Fetch BIOS version associated with bios system image')
        file = bios_image_path+ '/' + 'BIOSID.BIN'
        cfc_image_ver_file = subprocess.getoutput('ls '+file)
        if 'No such file or directory' in cfc_image_ver_file:
            log.error('BIOS CFC image version file does not exists')
            self.failed('BIOS Image version file BIOSID.BIN does not exists', goto=['CommonCleanup'])
        else:            
            cmd = 'cat ' + file
            classparam['bios_version'] = subprocess.check_output(cmd, shell=True).decode('utf_16').rstrip('\x00')
            print('============================')
            print(classparam['bios_version'])
            print('============================')            
#             with open(file, 'r') as fh:
#                 bios_version = fh.readline()
#             log.info('BIOS version is: '+bios_version)
#             classparam['bios_version'] = str(bios_version)
        
################# Common setup Ends ##############################################


################# Start of Testcase - verifyProcessorDetails #####################
# Logical ID: RACK-BIOS-Asset_tag -001/RACK-BIOS-IMC/ SMBIOS description -001
class DualFlashBiosUpdate(aetest.Testcase):
    '''
    Dual Flash BIOS Update Test Cases
    '''
    @aetest.setup
    def setup(self, cimc_util_obj):
        '''
        Test Case Setup
        '''
        log.info("Setup Section DualFlashBiosUpdate")
        firmware_utils_obj = classparam['firmware_utils']
        try:
            bios_image_path = os.environ['BIOS_IMAGE']
            log.info('BIOS Image Path:' + bios_image_path)
        except KeyError:
            self.skipped('SYSTEM IMAGE not provided in the env, please set system image and run',\
                         goto=['cleanup'])
        # Copying the BIOS CFC image file to TFTP share folder for BIOS update
        if firmware_utils_obj.prepare_bios_cfc_image_file(bios_image_path) is not True:
            self.failed('Failed to prepare BIOS image CFC file', goto=['cleanup'])
            
        # Collecting CIMC SEL log before the bios update/activate operation
        sel_log_before = cimc_util_obj.get_cimc_sel_log_latest_event(log_scope='sel')                                        
        classparam['sel_log_before'] = sel_log_before

    # RACK-BIOS-DN-BIOS Update and Activate-001
    # RACK-BIOS-DN-BIOS Update and Activate-002
    # RACK-BIOS-DN-BIOS Update and Activate-003
    host_power_states = ['off', 'on']
    @aetest.test.loop(uids=['host_power_off', 'host_power_on'], parameter=host_power_states)
    def update_activate_bios(self, cimc_util_obj, config, parameter):
        '''
        To verify the BIOS update through CIMC irrespective of the Host power state
        '''
        result = None
        # initialize the objects
        firmware_utils_obj = classparam['firmware_utils']
        actual_bios_ver = classparam['bios_version']        
        bios_obj = classparam['bios_obj']
        host_ip = classparam['host_ip']
               
        log.info('Updating BIOS image when host state is: '+ parameter)
        if cimc_util_obj.set_host_power(parameter) is False:
            self.failed('Failed to set the host power state to: ' + parameter)
        
        # update bios backup image 
        if firmware_utils_obj.bios_update_cfc_image() is not True:
            self.failed('Failed to Update the BIOS component', goto=['cleanup'])
        
        # RACK-BIOS-DN-BIOS Update and Activate-002
        if parameter == 'on':
            out = cimc_util_obj.handle.execute_cmd_list('top', 'scope bios', 'activate')
            if 'Please power off the system and then run this command' in out:
                log.info('Failed to activate bios when host is powered ON, as expected')
                result = 'PASS'
            else:
                log.error('Successfully activated bios when host is power ON, Not expected')
                result = 'FAIL'       
        
        if parameter == 'off':
            if firmware_utils_obj.activate_bios_image() is False:
                result = 'FAIL'
            
        # validate bios backup image with expected image
        bios_ver_after_update = get_bios_backup_version(cimc_util_obj)
        if bios_ver_after_update.strip() == actual_bios_ver.strip():
            log.info('Successfully verified that updated version is reflected in the Backup Version')
        else:
            log.error('Actual bios version is: %s, After Update bios version is: %s' %(actual_bios_ver, bios_ver_after_update))
            log.error('Failed to verify that updated version is reflected in Backup Version')
            result = 'FAIL'

        if result == 'FAIL':
            self.failed('Test Failed')
        else:
            self.passed('Test Passed')  
    
    # RACK-BIOS-DN-BIOS Update and Activate-004
    @aetest.test
    def verify_bios_version(self, cimc_util_obj):
        '''
        Validating BIOS version in post, and EFI
        '''
        host_serial_handle = cimc_util_obj.telnet_handle
        host_serial_handle.connect_to_host_serial()
        cimc_util_obj.power_cycle_host()
        bios_ver = classparam['bios_version']
        log.info('Expected string is: ' + str(bios_ver.encode()))
        res = host_serial_handle.validate_host_console_output(exp_string=bios_ver.encode())
        host_serial_handle.disconnect()
        if res is True:
            self.passed('Test Passed')
        else:
            self.failed('Test failed')
        
    @aetest.cleanup
    def cleanup(self, cimc_util_obj):
        '''
        Test Case Cleanup
        '''
        log.info('Cleanup section passed')
        sel_log_before = classparam['sel_log_before']
        sel_log_flag = cimc_util_obj.check_cimc_sel_log_diff_event(sel_log_before, log_scope='sel')        
        if sel_log_flag is False:
            self.failed('Found critical events after BIOS update/activate')
        else:
            self.passed('Not found any critical events after BIOS update/activate')

# RACK-BIOS-DN-BIOS Update and Activate-005
# RACK-BIOS-DN-BIOS Update and Activate-006            
# RACK-BIOS-DN-BIOS Update and Activate-007
# RACK-BIOS-DN-BIOS Update and Activate-008
# RACK-BIOS-DN-BIOS Update and Activate-009
# RACK-BIOS-DN-BIOS Update and Activate-010
# RACK-BIOS-DN-BIOS Update and Activate-011

class BiosUpdateAndVerify(aetest.Testcase):
    '''
    Retaining BIOS Tokens after BIOS update and activate
    Retaining BIOS Boot Order after BIOS update and activate
    '''
    @aetest.setup
    def setup(self, cimc_util_obj):
        '''
        Test Case Setup
        '''
        log.info("Setup Section BiosUpdateAndVerify")
          
        firmware_utils_obj = classparam['firmware_utils']
        bios_obj = classparam['bios_obj']
        host_ip = classparam['host_ip']        
        try:
            bios_image_path = os.environ['BIOS_IMAGE']
            log.info('BIOS Image Path:' + bios_image_path)
        except KeyError:
            self.skipped('SYSTEM IMAGE not provided in the env, please set system image and run',\
                         goto=['cleanup'])
        # Copying the BIOS CFC image file to TFTP share folder for BIOS update
        if firmware_utils_obj.prepare_bios_cfc_image_file(bios_image_path) is not True:
            self.failed('Failed to prepare BIOS image CFC file', goto=['cleanup'])
  
        log.info('Modify some of the tokens before start of BIOS update and activate')
        # create json profile and copy to remote tftp share
        if bios_obj.create_bios_profile_and_copy2tftpshare() is False:
            log.error('Failed to create bios json file on remote, continue test with existing token state')
        else:
            log.info('Successfully created and copied json format file to remote tftp share')
      
    @aetest.test
    def set_mfg_default_token(self, non_default_tokens=None):
        '''
        Verify Manufacturing Default settings are retained after 
        BIOS Update and Activate in BIOS Setup        
        '''
        bios_obj = classparam['bios_obj']
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
        classparam['user_token_dict'] = user_token_dict
        res = bios_obj.load_bios_mfg_custom_tokens(user_token_dict)
        if res is False:
            self.failed('Failed to load mfg bios tokens')
  
    @aetest.test
    def bios_tokens_capture(self, cimc_util_obj, testbed_name):
        '''
        Capture all bios tokens before update and activate
        '''
        bios_obj = classparam['bios_obj']
        host_ip = classparam['host_ip']        
        system_capture_object = classparam['system_capture_object']
        # Install and activate the bios profile on CIMC
        res = bios_obj.install_and_activate_bios_profile(reboot='yes')
        if res is True:
            log.info('Bios profile activation successful. Wait for host to come up')
            cimc_util_obj.verify_host_up(host_ip, wait_for_ping_fail=False)
          
        # Capture the bios token before start of update and activate
        output1 = cimc_util_obj.handle.execute_cmd_list(
            'top', 'scope bios', 'scope input-output', 'show detail')
        output1 = output1.split("---")
        output2 = cimc_util_obj.handle.execute_cmd_list(
            'top', 'scope bios', 'scope memory', 'show detail')
        output2 = output2.split("---")
        output3 = cimc_util_obj.handle.execute_cmd_list(
            'top', 'scope bios', 'scope power-or-performance', 'show detail')
        output3 = output3.split("---")
        output4 = cimc_util_obj.handle.execute_cmd_list(
            'top', 'scope bios', 'scope server-management', 'show detail')
        output4 = output4.split("---")
        output5 = cimc_util_obj.handle.execute_cmd_list(
            'top', 'scope bios', 'scope security', 'show detail')
        output5 = output5.split("---")
                          
        file_contents = output1[1] + "\n\r" + output2[1] + "\n\r" + output3[1] + "\n\r" + output4[1] + "\n\r" + output5[1]
        log.info('*** Bios token Before the update and activate: ***')
        log.info(str(file_contents))
        # generate the file
        token_file_before = "BIOS_Tokens_Info_Before_Update_Activate_" + testbed_name
        classparam['token_file_before'] = token_file_before
        file_creation_status = system_capture_object.generate_file_from_output(
            file_contents, token_file_before)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        else:
            self.passed('successfully captured and copied bios token file')        
      
    @aetest.test
    def boot_order_capture(self, cimc_util_obj, testbed_name):
        '''
        Capture boot order info before bios update and activate
        '''
        system_capture_object = classparam['system_capture_object']
        cimc_cli_handle = cimc_util_obj.handle
        output = cimc_cli_handle.execute_cmd_list(
            'top', 'scope bios', 'show actual-boot-order detail', wait_time=20)
        # parse the output
        lines = output.split("\n")
        file_contents = "Boot device : \n\r"
        for line in lines:
            line = line.strip()
            log.info("Line ...." + str(line))
            match_string = "DeviceName:\s+([^\n\r]+)"
            match_value = re.search(match_string, line)
            if match_value is not None:
                log.info("Match value...." + match_value.group(1))
                boot_dev_name = match_value.group(1)
                file_contents = file_contents + boot_dev_name + "\n\r"
        # save the output to the file
        filename = "Bootorder_info_before_update_" + testbed_name
        classparam['bo_file_before'] = filename
        file_creation_status = system_capture_object.generate_file_from_output(
            file_contents, filename)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
        else:
            self.passed('Successfully copied the boot order captured file')        
      
    @aetest.test
    def update_and_activate_bios(self, cimc_util_obj):
        '''
        To verify the BIOS update through CIMC irrespective of the Host power state
        '''
        # initialize the objects
        firmware_utils_obj = classparam['firmware_utils']
          
        # update and activate bios backup image 
        if firmware_utils_obj.bios_update_cfc_image(activate='yes') is not True:
            self.failed('Failed to Update and activate the BIOS image', goto=['cleanup'])
        else:
            self.passed('Successfully updated and activated BIOS image')
      
    @aetest.test
    def compare_bios_tokens_after_update(self, cimc_util_obj, testbed_name):
        '''
        Capture tokens after the BIOS update and activate and compare
        '''
        system_capture_object = classparam['system_capture_object']
          
        output1 = cimc_util_obj.handle.execute_cmd_list(
            'top', 'scope bios', 'scope input-output', 'show detail')
        output1 = output1.split("---")
        output2 = cimc_util_obj.handle.execute_cmd_list(
            'top', 'scope bios', 'scope memory', 'show detail')
        output2 = output2.split("---")
        output3 = cimc_util_obj.handle.execute_cmd_list(
            'top', 'scope bios', 'scope power-or-performance', 'show detail')
        output3 = output3.split("---")
        output4 = cimc_util_obj.handle.execute_cmd_list(
            'top', 'scope bios', 'scope server-management', 'show detail')
        output4 = output4.split("---")
        output5 = cimc_util_obj.handle.execute_cmd_list(
            'top', 'scope bios', 'scope security', 'show detail')
        output5 = output5.split("---")
  
        file_contents = output1[1] + "\n\r" + output2[1] + "\n\r" + output3[1] + "\n\r" + output4[1] + "\n\r" + output5[1]
        log.info('*** Bios token After the update and activate: ***')
        log.info(str(file_contents))
          
        # generate the file
        token_file_after = "BIOS_Tokens_After_Update_Activate_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            file_contents, token_file_after)
        if file_creation_status is False:
            self.failed("Error in generating the file " + filename)
          
        # check with the file std id available
        token_file_before = classparam['token_file_before']
        token_file_path = token_file_before
        log.info("....." + str(os.path.exists(token_file_path)))
        if os.path.exists(token_file_path):
            log.info(token_file_before + "is available for comparison")
            file_diff_status = system_capture_object.file_compare(
                token_file_before, token_file_after)
            if file_diff_status is True:
                log.info("Testcase Passed : no difference between " +
                            token_file_before + " and " + token_file_after)
                result = 'PASS'
            else:
                log.error(
                    "Testcase failed : There is  difference in tokens " + token_file_before + " and " + token_file_after)
                log.error("Testcase failed : There difference in tokens " +
                            token_file_before + " and " + token_file_after)
                result = 'FAIL'
        else:
            log.error("Testcase failed : STD file is not available for comparison: " + token_file_before)
            result = 'FAIL'
  
        if result == 'FAIL':
            self.failed('Test Failed')
        else:
            self.passed('Test Passed')
      
    @aetest.test
    def boot_order_compare(self, cimc_util_obj, testbed_name):
        '''
        Compares the Boot order info after the BIOS update and activate 
        '''
        system_capture_object = classparam['system_capture_object']
        cimc_cli_handle = cimc_util_obj.handle
        output_1 = cimc_cli_handle.execute_cmd_list(
            'top', 'scope bios', 'show actual-boot-order detail', wait_time=20)
        log.info(str(output_1))
        # parse the output
        lines = output_1.split("\n")
        file_contents = "Boot device : \n\r"
        for line in lines:
            line = line.strip()
            log.info("Line ...." + str(line))
            match_string = "DeviceName:\s+([^\n\r]+)"
            match_value = re.search(match_string, line)
            if match_value is not None:
                log.info("Match value...." + match_value.group(1))
                boot_dev_name = match_value.group(1)
                file_contents = file_contents + boot_dev_name + "\n\r"
        # save the output to the file
        bo_file_after = "Bootrder_info_after_update_" + testbed_name
        file_creation_status = system_capture_object.generate_file_from_output(
            file_contents, bo_file_after)
        if file_creation_status is False:
            log.error("Error in generating the file " + bo_file_after)
        else:
            log.info('Successfully copied the boot order captured file') 

        # check with the file std id available
        bo_file_before = classparam['bo_file_before']
        bo_file_path = bo_file_before
        log.info("....." + str(os.path.exists(bo_file_path)))
        if os.path.exists(bo_file_path):
            log.info(bo_file_before + "is available for comparison")
            file_diff_status = system_capture_object.file_compare(
                bo_file_before, bo_file_after)
            if file_diff_status is True:
                log.info("Testcase Passed : no difference between " +
                            bo_file_before + " and " + bo_file_after)
                result = 'PASS'
            else:
                log.error(
                    "Testcase failed : There is  difference in tokens " + bo_file_before + " and " + bo_file_after)
                log.error("Testcase failed : There difference in tokens " +
                            bo_file_before + " and " + bo_file_after)
                result = 'FAIL'
        else:
            log.error("Testcase failed : STD file is not available for comparison: " + bo_file_after)
            result = 'FAIL'
  
        if result == 'FAIL':
            self.failed('Test Failed')
        else:
            self.passed('Test Passed')    
          
    @aetest.test
    def validate_mfg_custom_default_tokens(self, cimc_util_obj):
        '''
        Test to verify retaining MFG Default settings - after BIOS update and activate
        '''
        bios_obj = classparam['bios_obj']
        user_token_dict = classparam['user_token_dict']
          
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
            out = bios_obj.validate_mfg_custom_default_tokens(bios_dict, user_token_dict, scope_name_dict[bios_scope])        
            if out is False:
                log.info('{} scope bios tokens are failed to match with expected default tokens'.format(bios_scope))
                result = 'Failed'
            else:
                log.info('{} scope bios tokens are validated successfully'.format(bios_scope))       
        if result == 'Failed':
            self.failed('Failed to retain MFG tokens after bios update and activate')
        else:
            self.passed('After BIOS update retained MFG default token')                
              
    @aetest.cleanup
    def cleanup(self, cimc_util_obj):
        '''
        Test Case Cleanup
        '''
        log.info('Cleanup section passed')            

class CommonCleanUp(Cleanup):
    ''' Common cleanup section'''
    @aetest.subsection
    def cleanup(self, cimc_util_obj):
        '''Cleanup'''
        super(CommonCleanUp, self).clean_everything(cimc_util_obj.handle)
