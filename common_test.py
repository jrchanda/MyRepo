# Needed for aetest script
import logging
from ats import aetest
from ats import easypy
from config_parser import ConfigParser
from linux_utils import LinuxUtils
from telnet_utils import TelnetUtil
import dumper
from cimc_utils import *

# Get your logger for your script
logger = logging.getLogger(__name__)

class Setup(aetest.CommonSetup):
    """ Common Setup section """
    
    @aetest.subsection
    def connect(self, testscript, testbed_name):
        """ Common Setup subsection : Will check whether the config file
            is present and if present,it will parse the config file, Also
            it will check for cimc and host access     
        """        
        logger.info("Aetest Common Setup ")
        logger.info("Testbed Config Common Setup %s " % testbed_name)

        config_parser = ConfigParser(testbed_name)
        config = testscript.parameters['config'] = config_parser.load_testbed_config()
        mgmt_detail = testscript.parameters['config'].mgmtdetail
        # HashMap for holding data across test sections 
        testscript.parameters['mgmt_handle'] = LinuxUtils(mgmt_detail.bmc_mgmt_ip,
                                       mgmt_detail.bmc_login,
                                       mgmt_detail.bmc_password)
        bmc_info = testscript.parameters['config'].bmc_info
        host_info = testscript.parameters['config'].host_info
        logger.info(dumper.dumps(testscript.parameters['config']))
        testscript.parameters['telnet_handle'] = TelnetUtil(bmc_info[0].bmc_serial.svr_ip,
                                        term_username=bmc_info[0].bmc_serial.login_name,
                                        term_password=bmc_info[0].bmc_serial.login_pwd,
                                        host_username=host_info[0].host_detail.os_login,
                                        host_password=host_info[0].host_detail.os_password,
                                        mgmnt_port=bmc_info[0].bmc_serial.svr_port,
                                        host_port=host_info[0].host_serial.svr_port,
                                        server_type=bmc_info[0].bmc_serial.svr_type)
        
        common_config = testscript.parameters['common_config'] = config_parser.load_common_config()
        
        tftp_ip = testscript.parameters['common_config'].tftp_share.tftp_server_ip
        tftp_user = testscript.parameters['common_config'].tftp_share.tftp_user
        tftp_password = testscript.parameters['common_config'].tftp_share.tftp_password
        tftp_root_dir = testscript.parameters['common_config'].tftp_share.tftp_root_path
        
        #testscript.parameters['tftp_handle']['ip: tftp_ip', 'user : tftp_user', 'password : tftp_password']
        #testscript.parameters['tftp_handle'] = LinuxUtils(tftp_ip, tftp_user, tftp_password)
        
        testscript.parameters['mgmt_handle'].connect()
        mgmt_handle = testscript.parameters['mgmt_handle']
        telnet_handle = testscript.parameters['telnet_handle']
        ntw_list = config.host_info[0].nw_intf_list
        logger.info('Management interface is:' + ntw_list[0].is_mgmt_intf)
        for intf in ntw_list:
            if intf.is_mgmt_intf == 'yes':
                logger.info('Host Managment IP is: ' + intf.ip_address)
                host_ip = intf.ip_address
        host_detail_obj = config.host_info[0].host_detail
        host_user = host_detail_obj.os_login
        host_passwd = host_detail_obj.os_password

        host_handle = testscript.parameters['host_handle'] = LinuxUtils(host_ip, host_user,host_passwd)

        testscript.parameters['cimc_util_obj'] = CimcUtils(mgmt_handle, telnet_handle, host_handle, config, common_config)
        logger.info(testscript.parameters['cimc_util_obj'])
        testscript.parameters['con_obj'] = config_parser.get_config_parser_obj()
        # print (self.mgmt_handle.execute_cmd('show chassis detail'))
        self.passed('setup pass')



        

#####################################################################
####                       COMMON CLEANUP SECTION                 ###
#####################################################################

class Cleanup(aetest.CommonCleanup):
    """ Common Cleanup for Sample Test """

    @aetest.subsection
    def clean_everything(self, mgmt_handle):
        """ Common Cleanup Subsection """
        logger.info("Aetest Common Cleanup ")
        mgmt_handle.disconnect()
        self.passed('cleanup pass')


        
