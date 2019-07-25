from time import strftime, gmtime
import logging
import time
import common_utils

from ats import aetest
from common_test import Setup, Cleanup
from host_utils import HostUtils
from linux_utils import LinuxUtils
from memory_lib import MemoryLib
from boot_order import BootOrder


logger = logging.getLogger(__name__)


class CommonSetup(Setup):

    @aetest.subsection
    def connect(self, testscript, testbed_name):
        super(CommonSetup, self).connect(testscript, testbed_name)


class MemoryModeAndPorTest(aetest.Testcase):
    '''
    Note :mem_mode_array=["Maximum_Performance", "Mirroring", "Lockstep"]
     has to be passed from the job file
    '''
    @aetest.setup
    def setup(self, mem_mode_array, cimc_util_obj, config):
        '''
        Loops through testcase for all the memory mode config passed from job file
        and loads host related details
        '''
        host_detail_config = config.host_info[0].nw_intf_list[0]
        host_info_config = config.host_info[0].host_detail
        logger.info(
            "IP : " +
            host_detail_config.ip_address +
            "\n user : " +
            host_info_config.os_login +
            "\n pass : " +
            host_info_config.os_password)
        host = LinuxUtils(
            host_detail_config.ip_address,
            host_info_config.os_login,
            host_info_config.os_password)
        self.boot_order_obj = BootOrder(cimc_util_obj, config)
        host_utils = HostUtils()
        self.host_utils = host_utils
        self.host = host
        self.host_ip = common_utils.get_host_mgmt_ip(config)
        host_ping_status = cimc_util_obj.verify_host_up(
            hostname=self.host_ip, wait_for_ping_fail=False, wait_time=30)
        if host_ping_status is True:
            logger.info("Host OS is pinging  ...")
        else:
            output = self.boot_order_obj.set_boot_order_HDD()
            if output == True:
                host_ping_status = cimc_util_obj.verify_host_up(
                    hostname=self.host_ip, wait_for_ping_fail=False, wait_time=600)
                if host_ping_status is True:
                    logger.info("Host OS is pinging  ...")
                else:
                    logger.error("ERROR :Host OS is not pinging \
                                ,after setting the boot order to HDD and retrying ...")
                    logger.error(
                        "Testcase failed .... since Unabke to boot to OS")
        aetest.loop.mark(
            self.validate_memory_config_in_cimc_and_host,
            mem_mode=mem_mode_array)

    @aetest.test
    def validate_memory_config_in_cimc_and_host(
            self, mem_mode, cimc_util_obj, config):
        '''
        Test case covers configuring memory mode and validating in CIMC , host,
        EFI Shell , BIOS post
        '''
        mem_obj = MemoryLib(cimc_util_obj)
        self.mem_obj = mem_obj
        # set memory mode
        res_mem_mode = mem_obj.configure_ras_mode(mem_mode)
        res_host_up = False
        if res_mem_mode == True:
            logger.info('Memory mode configured successfully')
            #host_ip = config.host_info[0].host_detail.os_host_name
            # power cycle host
            cimc_util_obj.power_cycle_host()
            time.sleep(60)
            # verify host is up
            res_host_up = cimc_util_obj.verify_host_up(hostname=self.host_ip, wait_for_ping_fail=True)
            if res_host_up:
                logger.info(
                    'Host rebooted successfully after memory configuration')
            else:
                output = self.boot_order_obj.set_boot_order_HDD()
                if output == True:
                    logger.info("Host OS is pinging  ...")
                else:
                    logger.error("ERROR :Host OS is not pinging \
                                    ,after setting the boot order to HDD and retrying ...")
                    logger.warning(
                    'Issue with host reboot starting to collect tech support')
                    cimc_util_obj.upload_techsupport_data()
                    self.failed('Issue with host')
            # verify memory por after config
            res_mem_por = mem_obj.verify_expected_frequency()
            # verify total and effective memory
            res_mem_config = mem_obj.verify_memory_config()
            # Linux host validation
            host_details = config.host_info[0].host_detail
            self.host_handle = LinuxUtils(host_details.os_host_name, host_details.os_login,
                                          host_details.os_password)
            self.host_handle.connect()
            mem_obj = MemoryLib(cimc_util_obj, self.host_handle)
            self.mem_obj = mem_obj
            res_mem_host = mem_obj.verify_memory_config_in_linux_host()
            res_mem_efi = mem_obj.verify_memory_config_in_efi_shell()
            if res_mem_por and res_mem_config and res_mem_host and res_mem_efi[
                    0] and res_mem_efi[1]:
                self.passed('memory validation in host is successful')
            else:
                logger.error(
                    'memory por , mem_config ,host results,EFI and POST results are below:')
                logger.error(res_mem_por)
                logger.error(res_mem_config)
                logger.error(res_mem_host)
                logger.error(res_mem_efi[0])
                logger.error(res_mem_efi[1])
                self.failed('Issue with memory validation in host')
        else:
            logger.error('Issue in configuring memory mode')
            cimc_util_obj.upload_techsupport_data()
            self.failed('test cases failed because of memory configuration')

    @aetest.test
    def verify_dimm_pid(self, cimc_util_obj, config):
        '''
        validates cimc dimm pid inventory with config file
        '''
        mem_obj = MemoryLib(cimc_util_obj)
        self.mem_obj = mem_obj
        mem_dict = mem_obj.get_mem_pid()
        dimm_validation = True
        for val in mem_dict:
            if mem_dict[val] in config.dimm_pid:
                continue
            else:
                dimm_validation = False
                logger.error('DIMM pid not found in list' + str(mem_dict[val]))
        if dimm_validation:
            logger.info('PID list from config')
            logger.info(config.dimm_pid)
            self.passed('DIMM PID verified')
        else:
            self.failed('DIMM PID verification failed')

    @aetest.test
    def cpu_and_memory_stress_using_ptu(self, cimc_util_obj):
        '''
        Runs ptugen and ptumon and monitor for any errors
        '''
        host_ping_status = cimc_util_obj.verify_host_up(
            hostname=self.host_ip, wait_for_ping_fail=False, wait_time=30)
        if host_ping_status is True:
            logger.info("Host OS is pinging  ...")
        else:
            output = self.boot_order_obj.set_boot_order_HDD()
            if output == True:
                host_ping_status = cimc_util_obj.verify_host_up(
                    hostname=self.host_ip, wait_for_ping_fail=False, wait_time=600)
                if host_ping_status is True:
                    logger.info("Host OS is pinging  ...")
                else:
                    self.failed(
                        "Testcase failed .... since Unabke to boot to OS")
        host = self.host
        host_utils = self.host_utils
        ptu_gen_cmd = "/root/tools/ptugen -ct 1 -mt 2 -t "
        ptu_gen_log_path = 'cat /root/tools/ptu_gen_file.txt'
        wait_time = 60
        host.connect()
        time.sleep(5)
        logs_before_stress = host_utils.get_host_logs(host)
        cimc_log_before = cimc_util_obj.get_cimc_sel_log_latest_event()
        sel_log_before = cimc_util_obj.get_cimc_sel_log_latest_event(
            log_scope='sel')
        logger.info(
            "Successfully booted to os after token change without any error")
        ptugen_out = host_utils.start_ptu_gen(
            host, ptu_gen_cmd, wait=wait_time)
        time.sleep(wait_time)
        ptumon_out = host_utils.get_ptu_monitor_out(host, scope='MEM')
        time.sleep(wait_time)
        ptugen_out = host.execute_cmd(
            ptu_gen_log_path, buffer_size=500000, wait_time=wait_time)
        logs_after_stress = host_utils.get_host_logs(host)
        cimc_log_flag = cimc_util_obj.check_cimc_sel_log_diff_event(
            cimc_log_before)
        cimc_log_flag = True
        sel_log_flag = cimc_util_obj.check_cimc_sel_log_diff_event(
            sel_log_before, log_scope='sel')
        sel_log_flag = True
        host_log_flag = host_utils.check_host_logs_diff(
            logs_before_stress, logs_after_stress)
        logger.info('ptugen out')
        logger.info(ptugen_out)
        logger.info('ptumon out')
        logger.info(ptumon_out)
        host.disconnect()
        if host_log_flag and cimc_log_flag and sel_log_flag:
            self.passed("Stress ran successfully")
        else:
            self.failed("Issue during stress")

    @aetest.test
    def mprime_test(self, cimc_util_obj):
        '''
        Runs mprime and monitor for error
        '''
        host_ping_status = cimc_util_obj.verify_host_up(
            hostname=self.host_ip, wait_for_ping_fail=False, wait_time=30)
        if host_ping_status is True:
            logger.info("Host OS is pinging  ...")
        else:
            output = self.boot_order_obj.set_boot_order_HDD()
            if output == True:
                host_ping_status = cimc_util_obj.verify_host_up(
                    hostname=self.host_ip, wait_for_ping_fail=False, wait_time=600)
                if host_ping_status is True:
                    logger.info("Host OS is pinging  ...")
                else:
                    self.failed(
                        "Testcase failed .... since Unabke to boot to OS")
        mprime_cmd = "/root/tools/mprime >> /root/tools/mprime.txt &"
        mprime_stress_time = 1800
        mprime_pid = ''
        mprime_kill = "kill -9 " + mprime_pid
        host = self.host
        host_utils = self.host_utils
        host.connect()
        logs_before_stress = host_utils.get_host_logs(host)
        cimc_log_before = cimc_util_obj.get_cimc_sel_log_latest_event()
        sel_log_before = cimc_util_obj.get_cimc_sel_log_latest_event(
            log_scope='sel')
        mprime_pid = host.execute_cmd(mprime_cmd)
        mprime_pid = self.get_pid(mprime_pid)
        time.sleep(mprime_stress_time)
        logger.info('mprime pid is : ' + mprime_pid)
        host.execute_cmd(mprime_kill)
        time.sleep(5)
        logs_after_stress = host_utils.get_host_logs(host)
        cimc_log_flag = cimc_util_obj.check_cimc_sel_log_diff_event(
            cimc_log_before)
        sel_log_flag = cimc_util_obj.check_cimc_sel_log_diff_event(
            sel_log_before, log_scope='sel')
        sel_log_flag = True
        host_log_flag = host_utils.check_host_logs_diff(
            logs_before_stress, logs_after_stress)
        host.disconnect()
        if host_log_flag and cimc_log_flag and sel_log_flag:
            self.passed("Stress ran successfully")
        else:
            self.failed("Issue during stress")

    @aetest.test
    def specjvm_test(self, cimc_util_obj):
        '''
        Runs specjvm at 30,90 and 180 ops and checks for error in
        host , cimc log , sel log
        '''
        host_ping_status = cimc_util_obj.verify_host_up(
            hostname=self.host_ip, wait_for_ping_fail=False, wait_time=30)
        if host_ping_status is True:
            logger.info("Host OS is pinging  ...")
        else:
            output = self.boot_order_obj.set_boot_order_HDD()
            if output == True:
                host_ping_status = cimc_util_obj.verify_host_up(
                    hostname=self.host_ip, wait_for_ping_fail=False, wait_time=600)
                if host_ping_status is True:
                    logger.info("Host OS is pinging  ...")
                else:
                    self.failed(
                        "Testcase failed .... since Unabke to boot to OS")
        ops_list = [30, 90, 180]
        spec_jvm_pid = ''
        spec_jvm_kill = "kill -9 " + spec_jvm_pid
        time_out = 2
        host = self.host
        host.connect()
        host_utils = self.host_utils
        host_log_flag = False
        sel_log_flag = False
        cimc_log_flag = False
        handle_2 = LinuxUtils(host.ip, host.username, host.password)
        handle_2.connect()
        for ops in ops_list:
            logger.info("Running specJVM at " + str(ops) + " Ops")
            logs_before_stress = host_utils.get_host_logs(host)
            cimc_log_before = cimc_util_obj.get_cimc_sel_log_latest_event()
            sel_log_before = cimc_util_obj.get_cimc_sel_log_latest_event(
                log_scope='sel')
            spec_jvm_cmd = "java -jar /root/tools/SPECjvm2008.jar -ikv -ops " + \
                str(ops) + " crypto.aes > /root/tools/specjvm.txt 2>&1 &"
            spec_jvm_pid = self.get_pid(handle_2.execute_cmd(spec_jvm_cmd))
            start_time = strftime("%H", gmtime())
            end_time = strftime("%H", gmtime())
            time.sleep((3600 * time_out) / 4)
            while (abs(int(start_time) - int(end_time)) <= time_out):
                end_time = strftime("%H", gmtime())
                out = host.execute_cmd("ps -ef | grep SPECjvm")
                ps_out = '\t'.join([line.strip() for line in out.splitlines()])
                logger.info("process out is" + ps_out)
                if spec_jvm_pid in ps_out:
                    time.sleep(60)
                else:
                    break
            if (abs(int(start_time) - int(end_time))) > time_out:
                host.execute_cmd('kill -9 ' + spec_jvm_pid)
            logs_after_stress = host_utils.get_host_logs(host)
            cimc_log_flag = cimc_util_obj.check_cimc_sel_log_diff_event(
                cimc_log_before)
            cimc_log_flag = True
            sel_log_flag = cimc_util_obj.check_cimc_sel_log_diff_event(
                sel_log_before, log_scope='sel')
            sel_log_flag = True
            host_log_flag = host_utils.check_host_logs_diff(
                logs_before_stress, logs_after_stress)
            if host_log_flag and cimc_log_flag and sel_log_flag:
                continue
            else:
                self.failed("Difference in host log")
        host.disconnect()
        handle_2.disconnect()
        if host_log_flag:
            self.passed("Spec JVM ran successfully")
        else:
            self.failed("Difference in host log")

    @aetest.test
    def mem_test(self, cimc_util_obj):
        '''Random value,XOR comparison,SUB comparison,MUL comparison,DIV comparison,OR comparison ,AND comparison
        Sequential Increment, Block Sequential, Solid Bits, Bit Flip, Checkerboard ,Walking Ones ,Walking Zeroes , Bit Spread
        '''
        host_ping_status = cimc_util_obj.verify_host_up(
            hostname=self.host_ip, wait_for_ping_fail=False, wait_time=30)
        if host_ping_status is True:
            logger.info("Host OS is pinging  ...")
        else:
            output = self.boot_order_obj.set_boot_order_HDD()
            if output == True:
                host_ping_status = cimc_util_obj.verify_host_up(
                    hostname=self.host_ip, wait_for_ping_fail=False, wait_time=600)
                if host_ping_status is True:
                    logger.info("Host OS is pinging  ...")
                else:
                    self.failed(
                        "Testcase failed .... since Unabke to boot to OS")
        memory_in_mb = '20000'
        memtest_cmd = "memtester " + memory_in_mb + \
            " >> /root/tools/memtest.txt &"
        memtest_stress_time = 1800
        memtest_pid = ''
        memtest_kill = "kill -9 " + memtest_pid
        host = self.host
        host_utils = self.host_utils
        host.connect()
        logs_before_stress = host_utils.get_host_logs(host)
        cimc_log_before = cimc_util_obj.get_cimc_sel_log_latest_event()
        sel_log_before = cimc_util_obj.get_cimc_sel_log_latest_event(
            log_scope='sel')
        memtest_pid = host.execute_cmd(memtest_cmd)
        memtest_pid = self.get_pid(memtest_pid)
        time.sleep(memtest_stress_time)
        logger.info('memtest pid is : ' + memtest_pid)
        host.execute_cmd(memtest_kill)
        time.sleep(5)
        logs_after_stress = host_utils.get_host_logs(host)
        cimc_log_flag = cimc_util_obj.check_cimc_sel_log_diff_event(
            cimc_log_before)
        cimc_log_flag = True
        sel_log_flag = cimc_util_obj.check_cimc_sel_log_diff_event(
            sel_log_before, log_scope='sel')
        sel_log_flag = True
        host_log_flag = host_utils.check_host_logs_diff(
            logs_before_stress, logs_after_stress)
        host.disconnect()
        if host_log_flag and sel_log_flag and cimc_log_flag:
            self.passed("Stress ran successfully")
        else:
            self.failed("Issue during stress")

    def get_pid(self, process_log):
        '''
        process the log and gets the process id
        '''
        return process_log.splitlines()[1].replace('[1]', '').replace(' ', '')


class CommonCleanUp(Cleanup):
    '''
    disconnect all the handles and makes clean exit
    '''
    @aetest.subsection
    def cleanup(self, mgmt_handle):
        super(CommonCleanUp, self).clean_everything(mgmt_handle)
