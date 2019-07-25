import logging
import time
import re
from linux_utils import LinuxUtils
import subprocess
import common_utils

logger = logging.getLogger(__name__)

class FirmwareUtils():
    def __init__(self, cimc_utils_obj, common_config, config=None):
        self.handle = cimc_utils_obj.handle
        self.cimc_utils_obj = cimc_utils_obj

        self.common_config = common_config
        
        self.tftp_ip = self.common_config.tftp_share.tftp_server_ip
        self.tftp_user = self.common_config.tftp_share.tftp_user
        self.tftp_password = self.common_config.tftp_share.tftp_password
        self.tftp_handle = LinuxUtils(self.tftp_ip, self.tftp_user, self.tftp_password)        
        self.tftp_root_dir = self.common_config.tftp_share.tftp_root_path        
        self.cap_image_file_path = None
        self.host_ip = common_utils.get_host_mgmt_ip(config)        
    
    def bios_update(self, protocol='tftp'):
        '''
        procedure to update BIOS firmware using default protocol
        Parameters:
            protocol:  protocol for the file transfer
            Address: IP address or Hostname of remote server
            PATH:  File path to BIOS firmware (.cap) file on the remote server
        Author: jchanda
        '''
        '''power off the host, it is required to update the bios firmware'''
        if self.cimc_utils_obj.set_host_power('off') is not True:
            logger.error('Failed to power off the host, aborting BIOS Upgrade')
            return False
        self.handle.execute_cmd_list('top', 'scope bios')
        if protocol is 'tftp':
            cap_image_file_path = '/'.join(self.cap_image_file_path.split('/')[2:4])
        bios_update_cmd = 'update' + ' ' + protocol + ' ' + self.tftp_ip + ' ' + cap_image_file_path
        logger.info('update command:' + bios_update_cmd)
        bios_out = self.handle.execute_cmd(bios_update_cmd, wait_time = 8)
        if 'bios update has started' in bios_out:
            logger.info('BIOS Update has started')
        else:
            logger.error('Failed to start BIOS Update. Command output: ' + bios_out)
            return False
        wait_time = 10
        logger.info('Sleep for ' + str(wait_time) + ' seconds before checking BIOS upgrade status')
        time.sleep(wait_time)
        upgrade_done = 0
        wait_time = 600
        max_wait_time = time.time() + wait_time
        while time.time() < max_wait_time:
            res = self.handle.execute_cmd('show detail')
            print (res)
            if re.search('fw-status: Done, OK', res, re.I):
                upgrade_done = 1
                break
            elif re.search('Error,', res, re.I):
                regex = 'Error,' + '\s*([^\\r\\n]+)'
                err_msg = re.search(regex, res).group(1)
                logger.error('BIOS Update failed: ' + err_msg)
                break
            else:
                logger.info('BIOS Firmware image download in-progress. Will continue to wait')
                time.sleep(5)

        if upgrade_done == 0:
            logger.info('Download failed or Exceeded max wait time ' + str(max_wait_time) + ' seconds')
            return False

        logger.info('Activating the backup BIOS version')
        if upgrade_done == 1:
            out2 = self.handle.execute_cmd('activate')
            if 'Continue' in out2:
                self.handle.execute_cmd('y')
            else:
                logger.error('Failed to activate the BIOS firmware')
                return False
        logger.info('BIOS update completed successfully')
        return True

    def bios_update_cfc_image(self, protocol='tftp', activate='no'):
        '''
        procedure to update BIOS CFC firmware using default protocol
        Parameters:
            protocol:  protocol for the file transfer
            Address: IP address or Hostname of remote server
            PATH:  File path to BIOS firmware (.cap) file on the remote server
        Author: jchanda
        '''
        self.handle.execute_cmd_list('top', 'scope bios')
        if protocol is 'tftp':
            cfc_image_file_path = '/'.join(self.cfc_image_file_path.split('/')[2:4])
        bios_update_cmd = 'update' + ' ' + protocol + ' ' + self.tftp_ip + ' ' + cfc_image_file_path
        logger.info('update command:' + bios_update_cmd)
        bios_out = self.handle.execute_cmd(bios_update_cmd, wait_time = 8)
        if 'bios update has started' in bios_out:
            logger.info('BIOS Update has started')
        else:
            logger.error('Failed to start BIOS Update. Command output: ' + bios_out)
            return False
        wait_time = 10
        logger.info('Sleep for ' + str(wait_time) + ' seconds before checking BIOS upgrade status')
        time.sleep(wait_time)
        upgrade_done = 0
        wait_time = 600
        max_wait_time = time.time() + wait_time
        while time.time() < max_wait_time:
            res = self.handle.execute_cmd('show detail')
            print (res)
            if re.search('fw-status: Done, OK', res, re.I):
                upgrade_done = 1
                break
            elif re.search('Error,', res, re.I):
                regex = 'Error,' + '\s*([^\\r\\n]+)'
                err_msg = re.search(regex, res).group(1)
                logger.error('BIOS Update failed: ' + err_msg)
                break
            else:
                logger.info('BIOS Firmware image download in-progress. Will continue to wait')
                time.sleep(5)

        if upgrade_done == 0:
            logger.info('Download failed or Exceeded max wait time ' + str(max_wait_time) + ' seconds')
            return False
        else:
            logger.info('Successfully updated the BIOS image on backup bank')
        
        if activate == 'yes':
            logger.info('Activating the backup BIOS version')
            # power off the host before activating backup bios
            if self.cimc_utils_obj.set_host_power('off') is not True:
                logger.error('Failed to power off the host, aborting BIOS Activate')
                return False            
            if upgrade_done == 1:
                self.handle.execute_cmd_list('top', 'scope bios')
                out2 = self.handle.execute_cmd('activate')
                if 'Continue' in out2:
                    self.handle.execute_cmd('y')
#                     res = self.cimc_utils_obj.verify_host_up(self.host_ip, wait_for_ping_fail=False)
#                     if res is False:
#                         logger.warning('Failed to ping the host after activating backup bios')
#                     else:
#                         logger.info("Host IP pinging successfully after activating backup bios")                    
                else:
                    logger.error('Failed to activate the BIOS firmware')
                    return False
            logger.info('BIOS update and activate successful')
            return True               
        else:
            logger.info('BIOS update completed successfully')
            return True

    def activate_bios_image(self):
        '''
        Procedure to activate BIOS backup image
        '''
        logger.info('Activating the backup BIOS version')
        # power off the host before activating backup bios
        if self.cimc_utils_obj.set_host_power('off') is not True:
            logger.error('Failed to power off the host, aborting BIOS activate')
            return False            

        self.handle.execute_cmd_list('top', 'scope bios')
        out = self.handle.execute_cmd('activate')
        if 'Continue' in out:
            self.handle.execute_cmd('y')
        elif 'Please power off the system and then run this command' in out:
            logger.error('Make sure host is powered OFF, before activating BIOS')
            return False
        else:
            logger.error('Failed to activate the BIOS firmware')
            return False
        logger.info('Successfully activated BIOS backup image')
        return True
    
    def prepare_bios_cfc_image_file(self, bios_image_path):
        '''
        Procedure to get extract the container zip file and fetch bios CAP file for update
        Parameter:
            system_image : container file in the form of zip file
        Return:
            True  : Success
            False : Failure
        Author: jchanda 
       '''
        logger.info('Copying the BIOS CFC image file to TFTP share folder for BIOS update')
        cmd = 'ls '+bios_image_path+ ' ' + '| grep cfc | grep -v D.cfc'        
        cfc_image_file = subprocess.getoutput(cmd)
        if 'No such file or directory' in cfc_image_file:
            logger.error('BIOS CFC image file does not exists')
            return False
        logger.info('BIOS CFC Image file: '+cfc_image_file)
        # Connect to remote TFTP filer server
        self.tftp_handle.connect()
        logger.info('Successfully connected to remote tftp server')
        logger.info('Creating dir in remote server')
        remote_path = self.tftp_root_dir+'/'+'bios_'+str(int(time.time()))
        self.tftp_handle.execute_cmd('mkdir -p ' +remote_path)
        
        logger.info('Copying the BIOS CFC image to remote tftp share server')
        res = self.tftp_handle.copy_local_to_remote(bios_image_path+'/'+str(cfc_image_file), remote_path+'/'+str(cfc_image_file))
        if res is not True:
            logger.error('Failed to copy bios cfc image file :' + cfc_image_file)
            return False
        else:
            logger.info('Successfully copied file: ' + cfc_image_file)
        
        #self.tftp_handle.execute_cmd('chmod 755' + ' ' + '../../../'+cap_file_name)
        self.cfc_image_file_path = remote_path+'/'+cfc_image_file       
        return True

    def prepare_bios_image_file(self, system_image):
        '''
        Procedure to get extract the container zip file and fetch bios CAP file for update
        Parameter:
            system_image : container file in the form of zip file
        Return:
            True  : Success
            False : Failure
        Author: jchanda
       '''
        logger.info('Extract zip file and set BIOS CAP file name for update')
        image_name = system_image.split('/')[-1]        
        self.tftp_handle.connect()
        logger.info('Successfully connected to remote tftp server')
        logger.info('Creating dir in remote server')
        remote_path = self.tftp_root_dir+'/'+'bios_'+str(int(time.time()))
        self.tftp_handle.execute_cmd('mkdir -p ' +remote_path)
        logger.info('Copying the system image to remote tftp share server')
        res = self.tftp_handle.copy_local_to_remote(system_image, remote_path+'/'+image_name)
        if res is not True:
            logger.error('Failed to copy file')
            return False
        else:
            logger.info('Successfully copied file')
        logger.info('Extracting the zip file, and fetch CAP file')
        self.tftp_handle.execute_cmd('cd ' +remote_path)
        time.sleep(1)
        self.tftp_handle.execute_cmd('unzip '+image_name)
        time.sleep(2)
        cap_file_dir = '*/bios/cimc'
        self.tftp_handle.execute_cmd('cd '+cap_file_dir)
        out = self.tftp_handle.execute_cmd('ls | grep -i cap | grep -i bios')
        for line in out.splitlines():
            if (re.search('\.cap', line, re.I)):
                cap_file_name = line.strip()
        logger.info('Cap file name for bios update: ' + cap_file_name)
        self.tftp_handle.execute_cmd('cp '+ cap_file_name + ' ' +'  ../../../'+cap_file_name)
        self.tftp_handle.execute_cmd('ls -l ' + ' ' + '../../../'+cap_file_name)
        self.tftp_handle.execute_cmd('chmod 755' + ' ' + '../../../'+cap_file_name)
        self.cap_image_file_path = remote_path+'/'+cap_file_name
        return True
        '''
        if os.path.exists(self.cap_image_file_path):
            logger.info('BIOS image CAP file on remote tftp server: {}'.format(self.cap_image_file_path))
            return True
        else:
            logger.error('BIOS image CAP file does not exists')
            return False
        '''
    def update_vic_firmware(self, adapter_slot, vic_fw_image, protocol='tftp'):
        '''
        procedure to update VIC firmware using default protocol
        Parameters:
            protocol:  protocol for the file transfer
            Address: IP address or Hostname of remote server
            PATH:  File path to VIC firmware file on the remote server
        Author: jchanda
        '''
        logger.info('Extract zip file and set BIOS CAP file name for update')
        image_name = vic_fw_image.split('/')[-1]
        self.tftp_handle.connect()
        logger.info('Successfully connected to remote tftp server')
        logger.info('Creating dir in remote server')
        remote_path = self.tftp_root_dir+'/'+'vic_'+str(int(time.time()))
        self.tftp_handle.execute_cmd('mkdir -p ' +remote_path)
        logger.info('Copying the VIC fw image to remote tftp share server')
        res = self.tftp_handle.copy_local_to_remote(vic_fw_image, remote_path+'/'+image_name)
        if res is not True:
            logger.error('Failed to copy file')
            return False
        else:
            logger.info('Successfully copied file')
        logger.info('Make sure that host is up')
        if self.cimc_utils_obj.set_host_power('on') is not True:
            logger.error('Failed to power cycle the host, aborting BIOS Upgrade')
            return False
        logger.info('Check whether VIC firmware image file exists on remote share server')
        vic_fw_file_path = remote_path+'/'+image_name
        out = self.tftp_handle.execute_cmd('ls '+vic_fw_file_path)
        if 'No such file or directory' in out:
            logger.warn('VIC firmware image {} not found in remote share server'.format(vic_fw_file_path))
            return 'SKIP'
        self.handle.execute_cmd_list('top', 'scope chassis')
        if protocol is 'tftp':
            vic_fw_file = '/'.join(vic_fw_file_path.split('/')[2:4])
        else:
            vic_fw_file = vic_fw_file_path
        vic_fiw_update_cmd = 'update-adapter-fw ' + protocol + ' ' + self.tftp_ip + ' ' + vic_fw_file + ' no-activate ' +adapter_slot
        vic_out = self.handle.execute_cmd(vic_fiw_update_cmd, wait_time = 60)
        if 'Adapter firmware update has started' in vic_out:
            logger.info('VIC firmware Update has started')
        else:
            logger.error('Failed to start VIC firmware update for adapter slot {}'.format(adapter_slot))
            return False
        upgrade_done = 0
        wait_time = 300
        max_wait_time = time.time() + wait_time
        while time.time() < max_wait_time:
            res = self.handle.execute_cmd('show adapter detail')
            if re.search('fw-update-status: Firmware update complete', res, re.I):
                upgrade_done = 1
                break
            elif re.search('Error,', res, re.I):
                regex = 'Error,' + '\s*([^\\r\\n]+)'
                err_msg = re.search(regex, res).group(1)
                logger.error('VIC firmware Update failed: ' + err_msg)
                break
            else:
                logger.info('VIC Firmware image download in-progress. Will continue to wait')
                time.sleep(2)
        if upgrade_done == 1:
            logger.info('VIC Firmware update completed successfully')
            return True
        else:
            logger.info('Download failed or Exceeded max wait time ' + str(max_wait_time) + ' seconds')
            return False       