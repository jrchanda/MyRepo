'''
__author__ = 'Suren Kumar Moorthy <suremoor@cisco.com>'
__copyright__ = 'Copyright 2016, Cisco Systems'
__email__ = 'suremoor@cisco.com'
__date__ = 'Nov 28,2016'
__version__ = 1.0
'''
# Needed for aetest script
import logging
import time
from ats import aetest
from linux_utils import LinuxUtils
from common_test import Setup, Cleanup
from processor_lib import ProcessorUtils
from host_utils import HostUtils
from boot_order import BootOrder

import common_utils

# Get your logger for your script
logger = logging.getLogger(__name__)
################################################################################
# Global class variable to maintain objects by creating one time and
# use all over the script
################################################################################

classparam = {}
################################################################################
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
    def initial_setup(self, cimc_util_obj):
        '''
        Initial Setups
        '''
        global classparam
        classparam['bios_obj'] = cimc_util_obj.bios_util_obj
        classparam['procc_obj'] = ProcessorUtils(classparam['bios_obj'])
        classparam['cpu_info'] = classparam['procc_obj'].get_cpu_info()
        classparam['host_utils'] = HostUtils()

################# Common setup Ends ##############################################

################# Start of Testcase - verifyProcessorDetails #####################

class VerifyProcessorDetails(aetest.Testcase):
    '''
        Verify Processor Details Testcases
    '''
    @aetest.setup
    def setup(self, cimc_util_obj, config):
        '''
        Test Case Setup
        '''
        logger.info("Setup Section verifyProcessorDetails")
        host_util = classparam['host_utils']
        procc_obj = ProcessorUtils(classparam['bios_obj'])
        out = classparam['procc_obj'].boot_order_obj.check_first_boot_device()
        logger.info(out)
#         if 'RAID' not in out:
#             if classparam['procc_obj'].boot_order_obj.change_boot_order() is False:
#                 self.failed("Unable to change boot order to hdd")
#             else:
#                 self.passed("Successfully changed boot order to hdd")

        status = host_util.check_host_up(cimc_util_obj, procc_obj.boot_order_obj, config)
        if status is False:
            logger.error('Host OS is not pinging after setting the boot order to HDD ')

    '''
        #######################################################
        Sub Test Case : verifyPID
        Logical ID : RACK-BIOS-DelNorte-Processor Feature-001
        #######################################################
    '''
    @aetest.test
    def verify_pid(self):
        '''
        Test Case verify_pid
        '''
        procc_obj = classparam['procc_obj']
        #Getting CPU info from cimc
        cpu_infos = classparam['cpu_info']
        fail_flag = 0
        #Verifying PID with config file
        for cpu_info in cpu_infos:
            logger.info("PID from cimc for "+ cpu_info.name + "  is "+cpu_info.pid)
            res = procc_obj.verify_cpu_info(cpu_info, "pid")
            if res is True:
                logger.info("PID verification for "+cpu_info.name+" is successful")
            else:
                logger.info("PID verification for "+cpu_info.name+" is failed")
                fail_flag = 1
        if fail_flag == 1:
            self.failed("PID verification failed")
        else:
            self.passed("PID verification passed for both the processor")
    #########################################################################################
    '''
        #######################################################
        Sub Test Case : verifiy_cpu_host
        Logical - ID : RACK-BIOS-DelNorte-Processor Feature-006
        #######################################################
    '''
    @aetest.test
    def verify_cpu_host(self, config):
        '''
        Test Case verify_cpu_host
        '''
        procc_obj = classparam['procc_obj']
        cpu_list = classparam['cpu_info']
        result = 'Pass'
        host_detail_config = config.host_info[0].nw_intf_list[0]
        host_info_config = config.host_info[0].host_detail
        logger.info("IP : "+host_detail_config.ip_address+ "\n user : "+host_info_config.os_login \
                    + "\n pass : "+host_info_config.os_password)
        host = LinuxUtils(host_detail_config.ip_address, \
                        host_info_config.os_login, host_info_config.os_password)
        host.connect()        
        cpu_host_info = procc_obj.get_cpu_info_host(host)
        logger.info("CPU OBJECT LIST")
        logger.info(cpu_list)
        host.disconnect()
        if len(cpu_list) > 0:
            thread_count_config = int(procc_obj.processor_config.thread_count) * len(cpu_list)
        else:
            self.failed("Error is getting CPU object list")

        if cpu_host_info['cores'] == procc_obj.processor_config.core_count:
            logger.info("Core count verification from host is successful")
        else:
            logger.error("Core count not matching : \n In host - " + str(cpu_host_info['cores']))
            logger.error("In Config : " + str(procc_obj.processor_config.core_count))
            result = 'Fail'

        if cpu_host_info['thread'] == thread_count_config:
            logger.info("Thread count verification from host is successful")
        else:
            logger.error("Thread count not matching : \n In host - " + str(cpu_host_info['thread']))
            logger.error("In Config : " + str(thread_count_config))
            result = 'Fail'
        if result == 'Pass':
            self.passed("Successfully verified core and thread in host")
        else:
            self.failed("Core and Thread verification failed")
    #########################################################################################
    '''
        #######################################################
        Sub Test Case : verify_cpuinfo_cimc
        Logical ID : RACK-BIOS-DelNorte-Processor Feature-004
        #######################################################
    '''
    @aetest.test
    def verify_cpuinfo_cimc(self):
        '''
        Test Case verify_cpuinfo_cimc
        '''
        #Creating Proccesor Object
        procc_obj = classparam['procc_obj']
        #Getting CPU info from cimc
        cpu_infos = classparam['cpu_info']
        token_list = ["manufacturer", "family", "thread_count", 'core_count', \
                          "version", "current_speed", "signature", 'cpu_status']
        fail_flag = 0
        #Verifying PID with config file
        for cpu_info in cpu_infos:
            logger.info("CPUinfo from cimc for {} ".format(cpu_info.name))
            for token in token_list:
                res = procc_obj.verify_cpu_info(cpu_info, token)
                if res is True:
                    logger.info("{} verification for {} is successful". \
                                format(getattr(cpu_info, token), cpu_info.name))
                else:
                    logger.error("{} verification for {} is failed". \
                                format(getattr(cpu_info, token), cpu_info.name))
                    fail_flag = 1

        if fail_flag == 1:
            self.failed("CPUinfo verification failed")
        else:
            self.passed("CPUinfo verification passed for both the processor")
    #########################################################################################

    '''
        #######################################################
        Sub Test Case : verify_host_after_bios_default
        Logical ID : RACK-BIOS-DelNorte-Processor Feature-002
        #######################################################
    '''
    @aetest.test
    def verify_host_after_bios_default(self, config, cimc_util_obj):
        '''
        Test Case verify_host_after_bios_default
        '''
        #Bios Config
        bios_obj = classparam['bios_obj']
        host_detail_config = config.host_info[0].nw_intf_list[0]
        host_info_config = config.host_info[0].host_detail
        if bios_obj.load_bios_defaults() is False:
            self.failed("Failed to load bios defaults")
        else:
            res_host_up = cimc_util_obj.verify_host_up(hostname=host_detail_config.ip_address, wait_for_ping_fail=False)
            if res_host_up:
                logger.info(
                    'Host rebooted successfully after bios defaults')
            else:
                logger.warning(
                    'Issue with host reboot after bios default')

        logger.info("IP : "+host_detail_config.ip_address+ "\n user : "+ \
                    host_info_config.os_login+ "\n pass : "+host_info_config.os_password)
        host = LinuxUtils(host_detail_config.ip_address,
                          host_info_config.os_login, host_info_config.os_password)
        if host.connect() is False:
            self.failed("Unable to connect to host")
        else:
            self.passed("Successfully booted to os after token change without any error")
            host.disconnect()

################## End of verifyProcessorDetails ######################################

################## Start of Testcase - verifyHyperThread ##############################
class VerifyHyperThread(aetest.Testcase):
    '''
        Hyper Thread Testcases
    '''

    '''
        #######################################################
        Sub Test Case : verifyHperThreadCores_All
                        verifyHperThreadCores_1
                        verifyHperThreadCores_2
                        verifyHperThreadCores_4
        Logical ID : RACK-BIOS-DelNorte-Processor Feature-034
        #######################################################
    '''
    PARAM_HYP = ['All', '1', '2', '4']
    @aetest.test.loop(uids=['verifyHperThreadCores_All', 'verifyHperThreadCores_1', \
    'verifyHperThreadCores_2', 'verifyHperThreadCores_4'], parameter=PARAM_HYP)
    def verfiy_hyper_thread(self, config, cimc_util_obj, parameter):
        bios_obj = classparam['bios_obj']
        host_util = classparam['host_utils']
        procc_obj = ProcessorUtils(classparam['bios_obj'])
        host_detail_config = config.host_info[0].nw_intf_list[0]
        host_info_config = config.host_info[0].host_detail
        ######## Bios Default #############################
        if bios_obj.load_bios_defaults() is False:
            self.failed("Failed to load bios defaults")
        else:
            res_host_up = cimc_util_obj.verify_host_up(hostname=host_detail_config.ip_address, wait_for_ping_fail=False)
            if res_host_up:
                logger.info(
                    'Host rebooted successfully after bios defaults')
            else:
                logger.warning(
                    'Issue with host reboot after bios default')
        ####################################################
        htpthd_value = bios_obj.get_bios_token_value('IntelHyperThread')
        logger.info("##########################################")
        logger.info("Currently Hyper Thread  Token is "+htpthd_value)
        logger.info("##########################################")
        if 'Enabled' not in htpthd_value:
            self.failed("Hyper Thread is not set to enabled")
        cores_enabled = bios_obj.get_bios_token_value('CoreMultiProcessing')
        if parameter != cores_enabled:
            if bios_obj.set_bios_token_value('CoreMultiProcessing', parameter,
                                             commit_wait=150) is False:
                self.failed("Failed to set core enabled to "+ parameter)
            else:
                cores_enabled1 = bios_obj.get_bios_token_value('CoreMultiProcessing')
                if parameter != cores_enabled1:
                    self.failed("Failed to set core enabled to "+parameter)
                logger.info("################################################")
                logger.info("Successfully set the core enabled to " + parameter)
                logger.info("################################################")

        logger.info("############## Host Info ####################")
        logger.info("IP : "+host_detail_config.ip_address+ "\n user : "+
                    host_info_config.os_login+ "\n pass : "+host_info_config.os_password)
        logger.info("#############################################")
        result = 'Pass'

        status = host_util.check_host_up(cimc_util_obj, procc_obj.boot_order_obj, config)
        if status is False:
            self.failed('Host is not up')
        host = LinuxUtils(host_detail_config.ip_address, host_info_config.os_login,
                          host_info_config.os_password)
        if host.connect() is False:
            self.failed("Unable to connect to host")
        else:
            logger.info("################################################################")
            logger.info("Successfully booted to os after token change without any error")
            logger.info("#################################################################")
            cpu_host_info = procc_obj.get_cpu_info_host(host)
            logger.info("Enabled cores is " + cores_enabled)
            if parameter == 'All':
                physical_core = int(procc_obj.processor_config.core_count)
            else:
                physical_core = int(parameter)
            cpu_list = classparam['cpu_info']
            logger.info("CPU list")
            logger.info(cpu_list)
            if len(cpu_list) > 0:
                calculated_logical_core = int(physical_core) * len(cpu_list) * 2
            else:
                self.failed("Error in getting CPU object")
            logger.info("################################################")
            logger.info("Logical and Physical values")
            logger.info("Logical : "+str(cpu_host_info['thread']))
            logger.info("Physical : "+str(physical_core))
            logger.info("################################################")
            if cpu_host_info['thread'] == calculated_logical_core:
                logger.info("Logical thread is equal to calculated logical core from physical core thread")
            else:
                logger.error("Logical Core not matching: \n Logical- " +
                             str(cpu_host_info['thread']) +"Calculated Logical core" + str(calculated_logical_core))
                result = 'Fail'
            host.disconnect()
            if result == 'Pass':
                self.passed("Physical and logical core comparison passed")
            else:
                self.failed("Physical and logical core comparison failed")

################# End of verifyHyperThread #################

########### Start of Testcase VerifyCPU_PTU ################
PARAM_DICT_PTU = {'All':'cpu_maxcore_turbo'}
PARAM_TOKEN = {'IntelTurboBoostTech':'cpu_expected_freq',
               'EnhancedIntelSpeedStep':'cpu_expected_freq'}

class VerifyCPUPTU(aetest.Testcase):
    '''
        VerifyCPUPTU Testcases
    '''
    '''
        #######################################################
        Sub Test Case : verify_processor_frequency_idlestate
        Logical ID :
            RACK-BIOS-DelNorte-Processor Feature-011
            RACK-BIOS-DelNorte-Processor Feature-044
        #######################################################
    '''
    @aetest.test
    def verify_processor_frequency_idlestate(self, config):
        bios_obj = classparam['bios_obj']
        procc_obj = classparam['procc_obj']
        host_util = classparam['host_utils']
        ######## Bios Default #############################
        if bios_obj.load_bios_defaults() is False:
            self.failed("Failed to load bios defaults")
        else:
            logger.info("Waiting for host to reboot after load bios default")
            time.sleep(180)
        ####################################################
        host_detail_config = config.host_info[0].nw_intf_list[0]
        host_info_config = config.host_info[0].host_detail
        logger.info("##### Host Detail ####################")
        logger.info("IP : "+host_detail_config.ip_address+ "\n user : "+
                    host_info_config.os_login+ "\n pass : "+host_info_config.os_password)
        logger.info("#####################################")
        host = LinuxUtils(host_detail_config.ip_address, host_info_config.os_login,
                          host_info_config.os_password)
        if host.connect() is False:
            self.failed("Unable to connect to host")
        else:
            logger.info("Successfully booted to os after token change without any error")
            logger.info("Keeping host for 5mins before PTU monitor")
            time.sleep(300)
            # Average frequency from ptu
            platform_type = config.mgmtdetail.platform_series
            avg_cpu_list = host_util.get_ptu_monitor_out(host, wait=600)
            if len(avg_cpu_list) < 1:
                self.failed("Error is getting average frequency")
            logger.info(avg_cpu_list)
            #idle_freq = round(float(procc_obj.processor_config.cpu_maxcore_turbo), 2)
            idle_freq = round(float(procc_obj.processor_config.cpu_lowest_freq), 2)
            logger.info('Idle frequency from config file is: ' + str(idle_freq))
            result = 'Pass'
            for ind, core_freq in enumerate(avg_cpu_list):
                if platform_type == 'M5':
                    core_freq = core_freq * 1000
                if core_freq-600 <= idle_freq <= core_freq+600:
                    logger.info("Successfully Verified core "+ str(ind) +
                                " frequency in idle state("+str(core_freq)+")")
                else:
                    logger.error("Core "+ str(ind) +
                                 " value not satisfied the idle frequency : "+ str(core_freq))
                    result = 'Fail'
            host.disconnect()
            if result == 'Pass':
                self.passed("Processor frequency verification for all cores successful")
            else:
                self.failed("Frequency value in idle state not matched with PTU value")

    '''
        #######################################################
        Sub Test Case : verify_cpu_frequencyEISTTurbo_All
        Logical ID :
            RACK-BIOS-DelNorte-Processor Feature-013
            RACK-BIOS-DelNorte-Processor Feature-046
        #######################################################
    '''
    PARAM_EIST = ['All']
    @aetest.test.loop(uids=['verify_cpu_frequencyEISTTurbo_All'], parameter=PARAM_EIST)
    def verify_cpu_frequency_eist_turbo(self, config, parameter):
        bios_obj = classparam['bios_obj']
        procc_obj = classparam['procc_obj']
        host_util = classparam['host_utils']
        ######## Bios Default #############################
        if bios_obj.load_bios_defaults() is False:
            self.failed("Failed to load bios defaults")
        else:
            logger.info("Waiting for host to reboot after load bios default")
            time.sleep(180)
        ###################################################
        host_detail_config = config.host_info[0].nw_intf_list[0]
        host_info_config = config.host_info[0].host_detail
        logger.info("############# Host Info ##########")
        logger.info("IP : "+host_detail_config.ip_address+"\n user : "+
                    host_info_config.os_login+ "\n pass : "+host_info_config.os_password)
        logger.info("##################################")
        result = 'Pass'
        host = LinuxUtils(host_detail_config.ip_address,
                          host_info_config.os_login, host_info_config.os_password)

        if host.connect() is False:
            self.failed("Unable to connect to host")
        else:
            logger.info("Successfully booted to os after token change without any error")
            eist_value = bios_obj.get_bios_token_value('EnhancedIntelSpeedStep')
            logger.info("Currently EIST is "+eist_value)
            turbo_value = bios_obj.get_bios_token_value('IntelTurboBoostTech')
            logger.info("Currently Turbo is "+turbo_value)
            if 'Enabled' not in eist_value:
                self.failed("Eist is not set to enabled")
            if 'Enabled' not in turbo_value:
                self.failed("Turbo is not set to enabled")
            cores_enabled = bios_obj.get_bios_token_value('CoreMultiProcessing')
            if parameter in cores_enabled:
                logger.info("Enabled cores is " + cores_enabled)
                logger.info("#########Param"+parameter+"########")
                logger.info(PARAM_DICT_PTU)
                logger.info("####################################")
                param_key = PARAM_DICT_PTU[parameter]
                logger.info("Config Key "+param_key)
                max_core_config = float(getattr(procc_obj.processor_config, param_key))
                logger.info("Config core val "+str(max_core_config))
                if host_util.start_ptu_gen(host, wait=600) is False:
                    self.failed("Failed to start PTU stress")
                    host.disconnect()
                else:
                    platform_type = config.mgmtdetail.platform_series
                    avg_cpu_list = host_util.get_ptu_monitor_out(host)
                    if len(avg_cpu_list) < 1:
                        self.failed("Error is getting average frequency")
                    for ind, core_freq in enumerate(avg_cpu_list):
                        if platform_type == 'M5':
                            core_freq = core_freq * 1000
                        if core_freq-1000 <= max_core_config <= core_freq+1000:
                            logger.info("Successfully Verified core "+ str(ind) +
                                        " frequency after stress when "+ parameter +
                                        " enabled :("+str(core_freq)+")")
                        else:
                            logger.error("Core "+ str(ind) +
                                         " value not satisfied with config : "+ str(core_freq))
                            result = 'Fail'
            else:
                self.failed("Expected cores not got enabled(" + cores_enabled + ")")
                host.disconnect()
            host.disconnect()
            if result == 'Pass':
                self.passed("Processor frequency verification for all cores successful")
            else:
                self.failed("Frequency value in idle state not matched with PTU value")

    '''
        #######################################################
        Sub Test Case :
            verifyCPUFrequencyDisableEIST
            verifyCPUFrequencyDisableTurbo
        Logical ID :
            RACK-BIOS-DelNorte-Processor Feature-087
            RACK-BIOS-DelNorte-Processor Feature-089
        #######################################################
    '''
    PARAM_EIST_DIS = ['EnhancedIntelSpeedStep', 'IntelTurboBoostTech']
    @aetest.test.loop(uids=['verifyCPUFrequencyDisableEIST',
                            'verifyCPUFrequencyDisableTurbo'], parameter=PARAM_EIST_DIS)
    def cpu_frequency_eist_turbo_ed(self, config, parameter, cimc_util_obj):
        bios_obj = classparam['bios_obj']
        procc_obj = classparam['procc_obj']
        host_util = classparam['host_utils']
        ######## Bios Default #############################
        if bios_obj.load_bios_defaults() is False:
            self.failed("Failed to load bios defaults")
        else:
            logger.info("Waiting for host to reboot after load bios default")
            time.sleep(180)
        ##################################################
        if bios_obj.set_bios_token_value(parameter, 'Disabled', commit_wait=150) is False:
            self.failed("Failed to Disable "+ parameter)
        else:
            turbo_value = bios_obj.get_bios_token_value(parameter)
            if 'Disabled' not in turbo_value:
                self.failed("Disabling "+parameter+" token failed")

        host_detail_config = config.host_info[0].nw_intf_list[0]
        host_info_config = config.host_info[0].host_detail
        logger.info("IP : "+host_detail_config.ip_address+ "\n user : "+
                    host_info_config.os_login+ "\n pass : "+host_info_config.os_password)
        result = 'Pass'
        host = LinuxUtils(host_detail_config.ip_address, host_info_config.os_login,
                          host_info_config.os_password)

        host_ip = common_utils.get_host_mgmt_ip(config)
        host_ping_status = cimc_util_obj.verify_host_up(
            hostname=host_ip, wait_for_ping_fail=False, wait_time=300)
        if host_ping_status is False:
            self.failed("Host OS is not pinging")
        if host.connect() is False:
            self.failed("Unable to connect to host")
        else:
            logger.info("Successfully booted to os after token change without any error")
            logger.info("Keeping host for 5mins before PTU monitor")
            time.sleep(300)
            param_key = PARAM_TOKEN[parameter]
            config_frequency = float(getattr(procc_obj.processor_config, param_key))
            logger.info("Config core val "+str(config_frequency))
            if host_util.start_ptu_gen(host, wait=60) is False:
                self.failed("Failed to start PTU stress")
                host.disconnect()
            else:
                platform_type = config.mgmtdetail.platform_series
                avg_cpu_list = host_util.get_ptu_monitor_out(host)
                if len(avg_cpu_list) < 1:
                    self.failed("Error is getting average frequency")
                for ind, core_freq in enumerate(avg_cpu_list):
                    if platform_type == 'M5':
                        core_freq = core_freq * 1000
                    if core_freq-1000 <= config_frequency <= core_freq+1000:
                        logger.info("Successfully Verified core "+ str(ind) +
                                    " frequency after stress when "+ parameter +
                                    " Disabled :("+str(core_freq)+")")
                    else:
                        logger.error("Core "+ str(ind) + " value not satisfied with config : "
                                     + str(core_freq))
                        result = 'Fail'
            host.disconnect()
            if result == 'Pass':
                self.passed("Processor frequency verification for all cores successful")
            else:
                self.failed("Frequency value in idle state not matched with PTU value")

################## End of Testcase VerifyCPU_PTU #################

##################################################################
################  Looping Parameter for msr testcase  ############
##################################################################
PARAM_DICT_MSR = {'IntelTurboBoostTech':['0000004000000000', 38, 0, 1],
                  'EnhancedIntelSpeedStep':['0000000000050000', 16, 1, 0],
                  'ExecuteDisable':['0000000400000000', 34, 0, 1],
                  'HardwarePrefetch':['0000000000000001', 0, 0, 1],
                  'AdjacentCacheLinePrefetch':['0000000000000002', 1, 0, 1],
                  'DirectCacheAccess':['0000000000000001', 0, 1, 0]}

PARAM_MSR = ['IntelTurboBoostTech', 'EnhancedIntelSpeedStep', 'ExecuteDisable', \
             'HardwarePrefetch', 'AdjacentCacheLinePrefetch', 'DirectCacheAccess']
#################################################################################################
'''
    #######################################################
    Test Cases :
        IntelTurboBoostTech
        EnhancedIntelSpeedStep
        ExecuteDisable
        HardwarePrefetch
        AdjacentCacheLinePrefetch
        DirectCacheAccess'
    Logical ID in order :
        1.RACK-BIOS-DelNorte-Processor Feature-063
        2.RACK-BIOS-DelNorte-Processor Feature-064
        3.RACK-BIOS-DelNorte-Processor Feature-068
        4.RACK-BIOS-DelNorte-Processor Feature-069
        5.RACK-BIOS-DelNorte-Processor Feature-066
        6.RACK-BIOS-DelNorte-Processor Feature-067
        7.RACK-BIOS-DelNorte-Processor Feature-071
        8.RACK-BIOS-DelNorte-Processor Feature-072
        9.RACK-BIOS-DelNorte-Processor Feature-073
        10.RACK-BIOS-DelNorte-Processor Feature-074
        11.RACK-BIOS-DelNorte-Processor Feature-075
        12.RACK-BIOS-DelNorte-Processor Feature-076
    #######################################################
'''
###################### Start of Msr Test case ###################################
@aetest.loop(uids=['VerifyTurboModeMsr', 'VerifyEistMsr', 'VerifyExecuteDisable', \
                   'VerifyHardware_Prefetcher', 'VerifyAdjacentCacheLine_Prefetch', \
                   'VerifyDirectCacheAccess'], parameter=PARAM_MSR)
class VerifyMSR(aetest.Testcase):

    @aetest.setup
    def setup(self, cimc_util_obj):
        '''
        Test Case Setup
        '''
        logger.info("Setup Section VerifyMSR")
        cimc_util_obj.handle.execute_cmd_list('top', 'scope sol', 'set enabled no', 'commit')

    @aetest.test.loop(uids=['Enabled', 'Disabled'], param_en_dis=['Enabled', 'Disabled'])
    def msr_enable_disable(self, parameter, param_en_dis, config):
        bios_obj = classparam['bios_obj']
        procc_obj = classparam['procc_obj']
        param_list = PARAM_DICT_MSR[parameter]
        if 'Enabled' in param_en_dis:
            verify_bit = param_list[2]
        else:
            verify_bit = param_list[3]
        ######## Bios Default #############################
        if bios_obj.load_bios_defaults() is False:
            self.failed("Failed to load bios defaults")
        else:
            logger.info("Waiting for host to reboot after load bios default")
            time.sleep(180)
        ###################################################
        # Getting Bios token

        platform_type = config.mgmtdetail.platform_series
        logger.info('Platform Series Type is: ' + platform_type)
        if platform_type == 'M4':
            token_dict_new = {'CpuPerformanceProfile':'Custom', parameter:param_en_dis}
        elif platform_type == 'M5':
            token_dict_new = {'CPUPerformance':'Custom', parameter:param_en_dis}

        token_value = bios_obj.get_bios_token_value(parameter)
        logger.info("Currently "+parameter+" is "+token_value)
        if param_en_dis in token_value:
            logger.info("Token value is Enables, Going to check the bit value")
            ret = procc_obj.verify_msr_mode(parameter, param_list[0], param_list[1], verify_bit)
            if ret is False:
                self.failed("Msr verify for some core failed")
            else:
                self.passed("Msr verificstion Passed")
        else:
            if 'HardwarePrefetch' in parameter or 'AdjacentCacheLinePrefetch' in parameter:
                #token_dict = {'CpuPerformanceProfile':'Custom', parameter:param_en_dis}
                token_dict = token_dict_new
                res = bios_obj.set_bios_token_value_list(token_dict, commit_wait=150)
            else:
                res = bios_obj.set_bios_token_value(parameter, param_en_dis,
                                                    commit_wait=150)
            if res is False:
                logger.error("Failed to Set the value")
            else:
                token_value1 = bios_obj.get_bios_token_value(parameter)
                if param_en_dis in token_value1:
                    logger.info("Token setting successful")
                    logger.info("Currently "+parameter+" is "+token_value1)
                else:
                    self.failed("Failed to enable the token")
                ret = procc_obj.verify_msr_mode(parameter, param_list[0], param_list[1], verify_bit)
                if ret is False:
                    self.failed("Msr verify for some core failed")
                else:
                    self.passed("Msr verificstion Passed")

#############################################################################
'''
    #######################################################
    Test Cases :
        LT_Locak_Memory_Msr
        Pkg_Cst_Config_Control
        Platform_Info
        Power_Ctl
        Dynamic_Switching_Enable
        Perf_Bias_Enable
        C1E_Enable'
    Logical ID in order :
        1.RACK-BIOS-DelNorte-Processor Feature-077
        2.RACK-BIOS-DelNorte-Processor Feature-078
        3.RACK-BIOS-DelNorte-Processor Feature-079
        4.RACK-BIOS-DelNorte-Processor Feature-080
        5.RACK-BIOS-DelNorte-Processor Feature-081
        6.RACK-BIOS-DelNorte-Processor Feature-082
        7.RACK-BIOS-DelNorte-Processor Feature-083
    #######################################################
'''
class VerifyMsrAfterBiosDefault(aetest.Testcase):
    @aetest.test
    def setup(self, cimc_util_obj):
        bios_obj = classparam['bios_obj']
        ######## Bios Default #############################
        if bios_obj.load_bios_defaults() is False:
            self.failed("Failed to load bios defaults")
        else:
            logger.info("Waiting for host to reboot after load bios default")
            time.sleep(180)
        cimc_util_obj.handle.execute_cmd_list('top', 'scope sol', 'set enabled no', 'commit')
    ########################################################

    ############### Parameter array for looping#################################
    PARAM_MSR_BD = ['lt_lock_memory,0000000000000009,0,1', 'pkg_cst,0000000000008000,15,1', \
             'plat_info,00000000F0000000,28,1', 'power_ctl,000000000B000000, 27, 1', \
             'dynamic_switch,000000000B000000,24,1', 'perf_bias,0000000000040000,18,1', \
             'c1e,000000000000000B,0,1']
    ############################################################################

    @aetest.test.loop(uids=['LT_Locak_Memory_Msr', 'Pkg_Cst_Config_Control',
                            'Platform_Info', 'Power_Ctl', 'Dynamic_Switching_Enable',
                            'Perf_Bias_Enable', 'C1E_Enable'], parameter=PARAM_MSR_BD)
    def msr_after_bios_default(self, parameter):
        procc_obj = classparam['procc_obj']
        param_list = parameter.split(",")
        logger.info("Verify msr for" + param_list[0])
        ret = procc_obj.verify_msr_mode(param_list[0], param_list[1], param_list[2], param_list[3])
        if ret is False:
            self.failed("Msr verify for some core failed")
        else:
            self.passed("Msr verify for all core Passed")

###################### End of Msr Test case ###################################

###################Start of SMBIOS Test case###################################

class VerifyCPUSMBIOS4(aetest.Testcase):

    '''
        #######################################################
        Test Case : verifiy_cpu_smbios_4
        Logical ID :
            1.RACK-BIOS-DelNorte-Processor Feature-008
            2.RACK-BIOS-DelNorte-Processor Feature-041
        #######################################################
    '''
    @aetest.test
    def verifiy_cpu_smbios_4(self):
        procc_obj = classparam['procc_obj']
        results = 'Pass'
        smbios_out = procc_obj.get_smbiosview_processor_param('4')
        token_list = ['smbios_version', 'current_speed', 'processor_upgrade', 'core_count']
        for token in token_list:
            if getattr(procc_obj.processor_config, token) == smbios_out[token]:
                logger.info("Processor info " + token + " verified from smbiosview 4 successfully")
                logger.info("Config :" + getattr(procc_obj.processor_config, token) +", Host: "+smbios_out[token])
            else:
                results = 'Fail'
                logger.info("Config :" + getattr(procc_obj.processor_config, token) +", Host: "+smbios_out[token])
                logger.error("Failed to verify "+token+" with smbiosview 4")
        if results == 'Fail':
            self.failed("SMBIOS veiw 4 verification failed")
        else:
            self.passed("All token got verified successfully")
    '''
        #######################################################
        Test Case : verifiy_cpu_smbios_7
        Logical ID :
        RACK-BIOS-DelNorte-Processor Feature-009
        RACK-BIOS-DelNorte-Processor Feature-042
        #######################################################
    '''
    @aetest.test
    def verifiy_cpu_smbios_7(self):
        bios_obj = classparam['bios_obj']
        procc_obj = classparam['procc_obj']
        results = 'Pass'

        smbios_out = procc_obj.get_smbiosview_processor_param('7')
        if smbios_out is False:
            self.failed("Issue in smbios view output")
        verify_list = ['l1_cache', 'l1_cache_p', 'l2_cache', 'l2_cache']
        for index, smbios_dict in enumerate(smbios_out):
            logger.info("Verifying smbios 7 for cpu "+ str(index+1))
            for tok in verify_list:
                res = getattr(procc_obj.processor_config, tok)
                for verify_ele in res.split(","):
                    key_value_array = verify_ele.split(":")
                    if key_value_array[1] == smbios_dict[tok][key_value_array[0]]:
                        logger.info("Processor info " + tok + "->" + key_value_array[0] +
                                    ":" + key_value_array[1] +
                                    " verified from smbiosview 7 successfully")
                    else:
                        results = 'Fail'
                        logger.error("Failed to verify " + tok + "->" + key_value_array[0] +
                                     ":" + key_value_array[1] +" with smbiosview 7")
        if results == 'Fail':
            self.failed("SMBIOS veiw 7 verification failed")
        else:
            self.passed("All token got verified successfully")


###################End of SMBIOS Test case###################################

class CommonCleanUp(Cleanup):

    @aetest.subsection
    def cleanup(self, mgmt_handle):
        super(CommonCleanUp, self).clean_everything(mgmt_handle)
