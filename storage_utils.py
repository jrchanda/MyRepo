'''
storage_utils.py
Created Class for storage related 

'''
import logging
import time
import re

logger = logging.getLogger(__name__)

__author__ = 'Jagadish Chanda <jchanda@cisco.com>'
__copyright__ = 'Copyright 2017, Cisco Systems'
__email__ = 'jchanda@cisco.com'
__date__ = 'Feb 27,2017'
__version__ = 1.0

log = logging.getLogger(__name__)


class StorageUtils():
    '''
    Storage Utils Class
    '''

    def __init__(self, cimc_utils_obj, config=None):
        self.cimc_utils_obj = cimc_utils_obj
        self.mgmt_handle = cimc_utils_obj.handle
        self.host_handle = cimc_utils_obj.host_handle
        self.config = config

    def configure_boot_vd(self, os_vd_no='0'):
        '''Procedure to create configure boot VD'''
        log.info('Configuring boot VD')
        self.get_storage_adapter_slot()
        slot = self.storage_adpter_slot
        log.info('Make sure host is power on')
        if self.cimc_utils_obj.set_host_power('on') is False:
            return False
        time.sleep(60)
        log.info('Setting VD no. {} to boot drive'.format(os_vd_no))
        self.mgmt_handle.execute_cmd_list('top', 'scope chassis', 'scope storageadapter ' + slot,
                                          'scope virtual-drive ' + os_vd_no)
        out = self.mgmt_handle.execute_cmd('set-boot-drive')
        if 'Enter \'yes\' to confirm' in out:
            self.mgmt_handle.execute_cmd('yes')
        else:
            log.error('Failed to set boot drive on VD ' + os_vd_no)
            return False
        time.sleep(2)
        out = self.mgmt_handle.execute_cmd('show detail', wait_time=8)
        match = re.search(r'is-boot-drive:\s+true', out)
        if match is None:
            log.error('After setting VD {} to boot drive, it is not reflecting'.format(os_vd_no))
            return False
        else:
            log.info('Successfully set VD {} to boot drive'.format(os_vd_no))
            return True
        
    def configure_boot_pd(self, os_pd_no='0'):
        '''Procedure to create configure boot PD'''
        log.info('Configuring boot PD')
        self.get_storage_adapter_slot()
        slot = self.storage_adpter_slot
        log.info('Make sure host is power on')
        if self.cimc_utils_obj.set_host_power('on') is False:
            return False
        time.sleep(60)
        log.info('Setting PD no. {} to boot drive'.format(os_pd_no))
        self.mgmt_handle.execute_cmd_list('top', 'scope chassis', 'scope storageadapter ' + slot,
                                          'scope physical-drive ' + os_pd_no)
        out = self.mgmt_handle.execute_cmd('set-boot-drive')
        if 'Enter \'yes\' to confirm' in out:
            self.mgmt_handle.execute_cmd('yes')
        else:
            log.error('Failed to set boot drive on PD ' + os_pd_no)
            return False
        time.sleep(2)
        out = self.mgmt_handle.execute_cmd('show detail', wait_time=8)
        match = re.search(r'is-boot-drive:\s+true', out)
        if match is None:
            log.error('After setting PD {} to boot drive, it is not reflecting'.format(os_pd_no))
            return False
        else:
            log.info('Successfully set PD {} to boot drive'.format(os_pd_no))
            return True

    def get_storage_adapter_slot(self):
        '''Procedure to storage adapter slot'''
        log.info('Fetching the storage adapter slot')
        # storage_cntl_out = self.cimc_utils_obj.get_scope_output('top', 'scope chassis',
        #                                                        cmnd='show storageadapter detail')
        storage_cntl_out = self.mgmt_handle.execute_cmd_list('top', 'scope chassis',
                                                              'show storageadapter detail', wait_time=10)
        log.info('Storage adapter detail: ' + storage_cntl_out)
        controller = re.search(r'controller:\s+([^\r\n]+)', storage_cntl_out).group(1)
        logger.info('Controller is: ' + controller)
        out = re.search('SLOT-HBA', controller)
        if out is not None:
            slot = 'HBA'
        out = re.search('-([0-9]+)', controller)
        if out is not None:
            slot = out.group(1)
        out = re.search('SAS', controller)
        if out is not None:
            slot = '11'
        out = re.search('SLOT-MEZZ', controller)
        if out is not None:
            slot = 'M'
        out = re.search('MRAID', controller)
        if out is not None:
            slot = 'MRAID'
        log.info('Storage adapter slot: ' + slot)
        self.storage_adpter_slot = controller
        return slot

