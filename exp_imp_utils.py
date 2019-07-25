import logging
import time
import re
from linux_utils import LinuxUtils
from vic_lib import VicLib
from common_utils import dump_error_in_lib

logger = logging.getLogger(__name__)

class ExpImpUtils():
    def __init__(self, cimc_utils_obj, config, common_config):
        self.cimc_utils_obj = cimc_utils_obj
        self.handle = cimc_utils_obj.handle
        self.config = config
        self.common_config = common_config
        
        self.tftp_ip = self.common_config.tftp_share.tftp_server_ip
        self.tftp_user = self.common_config.tftp_share.tftp_user
        self.tftp_password = self.common_config.tftp_share.tftp_password
        self.tftp_handle = LinuxUtils(self.tftp_ip, self.tftp_user, self.tftp_password)        
        self.tftp_root_dir = self.common_config.tftp_share.tftp_root_path        
        self.export_path = None        
    
    def export_vic_config(self, slot_no, protocol='tftp', server=None, path=None, user=None, password=None):
        '''
        Procedure to export VIC configuration
        Parameter:
            slot_no: slot number on adapter card is present
            protocol: Protocol to use { tftp | ftp | sftp | scp | http }
            server: Remote server IP address
            path:  Image file path on the remote server
            user: remote server user name
            password: remote server user password
        Return:
            True  : Success
            False : Failure
        '''
        try:
            if server == None:
                remote_dir = '/vic_export/'
                remote_path = self.tftp_root_dir+remote_dir
                self.tftp_handle.connect()
                logger.info('Successfully connected to remote tftp server')
                self.tftp_handle.execute_cmd_list('mkdir -p ' +remote_path)
                self.tftp_handle.execute_cmd_list('chmod 777 ' +remote_path)
                self.tftp_handle.disconnect()             
               
            self.handle.execute_cmd_list('top', 'scope chassis', 'scope adapter ' + slot_no)
            vic_xml_file="vic_config" + "_" + "slot_no_" + slot_no
            if protocol is 'tftp' or protocol is 'http':
                out = self.handle.execute_cmd('export-vnic' + ' ' + protocol + ' ' + self.tftp_ip + ' ' + remote_dir+vic_xml_file, wait_time=6)                
                if 'Export succeeded' in out:
                    logger.info('VIC export operation completed successfully: ' + remote_path+vic_xml_file)
                    self.export_path = remote_path+vic_xml_file
                else:
                    logger.exception('Failed to export VIC config data')
                    return False
            elif protocol is 'sftp' or protocol is 'scp':
                out = self.handle.execute_cmd('export-vnic' + ' ' + protocol + ' ' + self.tftp_ip + ' ' + remote_path+vic_xml_file, wait_time=6)
                if 'Do you wish to continue' in out:
                    self.handle.execute_cmd('y')
                    time.sleep(1)
                    self.handle.execute_cmd(user)
                    time.sleep(1)
                    out = self.handle.execute_cmd(password, wait_time=6)                   
                    if 'Export succeeded' in out:
                        logger.info('VIC export operation completed successfully')
                        self.export_path = remote_path+vic_xml_file                      
                    else:
                        logger.exception('Failed to export VIC config data')
                        return False
            elif protocol is 'ftp':
                self.handle.execute_cmd('export-vnic' + ' ' + protocol + ' ' + self.tftp_ip + ' ' + remote_dir+vic_xml_file, wait_time=6)
                self.handle.execute_cmd(user)
                time.sleep(1)
                out = self.handle.execute_cmd(password, wait_time=6)
                if 'Export succeeded' in out:
                    logger.info('VIC export operation completed successfully')
                    self.export_path = remote_path+vic_xml_file                  
                else:
                    logger.exception('Failed to export VIC config data')
                    return False
            else:
                logger.error('Invalid protocol selected')
                return False
            return True
        except:
            dump_error_in_lib()
            return False
    def validate_vic_config(self, slot_no):        
        logger.info("Verifying the VIC configuration exported for slot no " + slot_no)
        self.tftp_handle.connect()
        out = self.tftp_handle.execute_cmd('cat ' + self.export_path + ' | ' + 'grep -F "<CDN>"')
        self.tftp_handle.disconnect()

        cdn_name_from_export = re.findall(r'<CDN>(\w+)<\/CDN>', out)
        logger.info('exported CDN_names are')
        logger.info(cdn_name_from_export)
        
        logger.info('Fetching CDN name from CIMC CLI')
        vic_obj = VicLib(self.cimc_utils_obj, self.config)
        out = vic_obj.cimc_cdn_mac_dict(slot_no)
        cnd_name_from_cimc = []
        for cdn_name in out.values():
            cnd_name_from_cimc.append(cdn_name)
        logger.info ('CDN Name from CIMC list:' + str(cnd_name_from_cimc))
        '''
        if len(cnd_name_from_cimc) != len(cdn_name_from_export):
            logger.error('Both lists have different size lengths')
            return False
        '''
        for val in cdn_name_from_export:
            if val not in cnd_name_from_cimc:
                logger.info("From CIMC CDN name are not same as TSR CDN name")
                return False
        return True
    def remove_vic_config(self):
        '''
        Procedure to remove the VIC exported file
        Returns:
            True: on success
            False: on failure
        '''
        try:
            logger.info('Deleting vic export config file: ' + self.export_path)
            self.tftp_handle.connect()
            self.tftp_handle.execute_cmd('rm -f ' + self.export_path)
            self.tftp_handle.disconnect()
        except:
            dump_error_in_lib()        