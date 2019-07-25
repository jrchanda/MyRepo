import logging
import re
import time
from common_utils import dump_error_in_lib
from linux_utils import LinuxUtils
from windows_utils import WindowsUtil

__author__ = 'Jagadish Chanda <jchanda@cisco.com>'
__copyright__ = 'Copyright 2016, Cisco Systems'
__email__ = 'jchanda@cisco.com'
__date__ = 'Sept 28, 2016'
__version__ = 1.0

'''
vic_lib.py

Class contains all vic related procedures
'''

logger = logging.getLogger(__name__)

class HostEthInt():
    '''
    Holding Host Ethernet Interface details
    '''
    def __init__(self, name, mtu, uplink, mac_addr, cos, trust_host_cos, pci_link, order, vlan,
                 rate_limit, boot, iscsi_boot, usnic_count, channel_number, port_profile,
                 uplink_failover, uplink_failback_timeout, arfs, vmq, nvgre, vxlan, CDN, rdma_qp, rdma_mr, rdma_resgrp):
        self.name = name
        self.mtu = mtu
        self.uplink = uplink
        self.mac_addr = mac_addr
        self.cos = cos
        self.trust_host_cos = trust_host_cos
        self.pci_link = pci_link
        self.order = order
        self.vlan = vlan
        self.rate_limit = rate_limit
        self.boot = boot
        self.iscsi_boot = iscsi_boot
        self.usnic_count = usnic_count
        self.channel_number = channel_number
        self.port_profile = port_profile
        self.uplink_failover = uplink_failover
        self.uplink_failback_timeout = uplink_failback_timeout
        self.arfs = arfs
        self.vmq = vmq
        self.nvgre = nvgre
        self.vxlan = vxlan
        self.CDN = CDN
        self.rdma_qp = rdma_qp
        self.rdma_mr = rdma_mr
        self.rdma_resgrp = rdma_resgrp

class VicLib(object):
    def __init__(self, cimc_obj, config):
        self.handle = cimc_obj.handle
        self.eth_int_details = []
        self.cimc_obj = cimc_obj
        self.config = config
        self.export_path = None
    def create_vnic(self, slot_no, *dev_name, cdn_name='None', channel='None', profile='None'):
        '''
        Procedure to create new host-eth-if and configures channel and port profile
        Parameter:
            slot_no: slot number on device inserted
            dev_name: list of device names. e.g: eth2, eth3
            channel: channel number
            profile: port profile on the switch
        Return:
            True  : Success
            False : Failure
        '''
        try:
            logger.info('Creating vnic interface')
            self.handle.execute_cmd_list('top', 'scope chassis', 'scope adapter ' + str(slot_no))
            for devname in dev_name:
                out = self.handle.execute_cmd('create host-eth-if ' + devname, wait_time=15)
                match1 = re.search('Failed|invalid|Error', out, re.I)
                if match1 is not None:
                    logger.error('Failed to execute command, create host-eth-if; got error as: ' + str(out))
                    self.handle.execute_cmd('discard')
                    return False
                if cdn_name is not 'None':
                    logger.info('Setting unique CDN name on interface ' + cdn_name)
                    cdn_out = self.handle.execute_cmd('set CDN ' + cdn_name, wait_time=15)                    
                    match2 = re.search('Failed|invalid|Error', cdn_out, re.I)
                    if match2 is not None:
                        logger.error('Failed to execute command, set CDN; got error as: ' + str(cdn_out))
                        self.handle.execute_cmd('discard')
                        return False
                    elif 'Duplicate CDN name exists, discarding it' in cdn_out:
                        self.handle.execute_cmd_list('discard')
                        return cdn_out
                if channel is not 'None' and profile is not 'None':
                    out1 = self.handle.execute_cmd('set channel-number ' + channel)
                    out2 = self.handle.execute_cmd('set port-profile ' + profile)
                    match = re.search('Failed|invalid|Error', out1+out2, re.I)
                    if match is not None:
                        logger.error('Failed to execute command, set channel-number; got error as: ' + str(out1+out2))
                        self.handle.execute_cmd('discard')
                        return False
            out = self.handle.execute_cmd('commit', wait_time=12)
            if 'Committed host-eth-if' in out:
                logger.info('Successfully created vnic interface')
                return True
            else:
                self.handle.execute_cmd_list('discard')
                return False
        except:
            dump_error_in_lib()
            return False
    def modify_vnic_properties(self, slot_no, dev_name, vnic_attr, vnic_attr_value):
        '''
        Procedure to modify or update vnic parameters properties
        Parameter:
            slot_no: slot number on where interface device created
            dev_name: name of device e.g: eth2
            vnic_attr: attribute of vnic interface to be modify. e.g: CDN
            vnic_attr_value: new attribute value to be applied on vnic attribute
        Return:
            True  : Success
            False : Failure
        '''
        try:
            logger.info('Modifying vnic interface CDN name')
            self.handle.execute_cmd_list('top', 'scope chassis', 'scope adapter ' + str(slot_no))
            out = self.handle.execute_cmd('scope host-eth-if ' +dev_name, wait_time=6)
            if 'Error:' in out:
                logger.error('Failed to execute command: got error: ' + out)
                return False
            self.handle.execute_cmd('set ' + vnic_attr + ' ' + vnic_attr_value)
            match = re.search('Failed|invalid|Error', out, re.I)
            if match is not None:
                logger.error('Failed to execute command; got error as: ' + str(match))
                return False
            out = self.handle.execute_cmd('commit', wait_time=10)
            if 'Committed host-eth-if' in out:
                logger.info('Successfully modified vnic attribute for ' + vnic_attr)
                return True
            else:
                self.handle.execute_cmd('discard')
                logger.error('Failed to modify the VNIC interface attribute values')
                return False
        except:
            dump_error_in_lib()
            return False
    def delete_vnic(self, slot_no, dev_name):
        '''
        Procedure to delete vnic interface
        Parameter:
            slot_no: slot number on interface device is created
            dev_name: name of device e.g: eth2
        Return:
            True  : Success
            False : Failure
        '''
        try:
            logger.info('Deleting the vnic interface')
            out = self.handle.execute_cmd_list('top', 'scope chassis', 'scope adapter ' + str(slot_no), wait_time = 6)
            if 'Error: Managed object does not exist' in out:
                logger.error('vnic interface {} does not exists'.format(dev_name))
                return False
            self.handle.execute_cmd('delete  host-eth-if ' + dev_name, wait_time=12)
            out = self.handle.execute_cmd('commit', wait_time=10)
            if 'Deleted host-eth-if' in out:
                logger.info('Successfully deleted vnic interface ' + dev_name)
                return True
            else:
                logger.error('Failed to delete vnic interface ' + dev_name)
                return False
        except:
            dump_error_in_lib()
            return False

    def get_host_eth_int_details(self, adapter_slot):
        '''
        Get Host Ethernet interface Details
        Procedure to load the Ethernet intf detail in HostEthInt object

        Return:
            Object populated with host eth interface details : SUCCESS
            False : FAILURE

        Author : jchanda
        '''
        try:
            self.handle.execute_cmd_list('top', 'scope chassis', 'scope adapter ' + adapter_slot)
            output = self.handle.execute_cmd('show host-eth-if detail', wait_time=15)
            attr_list = ['name', 'mtu', 'uplink', 'mac-addr', 'cos', 'trust-host-cos', 'pci-link', 'order', 'vlan',
                 'rate-limit', 'boot', 'iscsi-boot', 'usnic-count', 'channel-number', 'port-profile', 'uplink-failover',
                 'uplink-failback-timeout', 'arfs', 'vmq', 'nvgre', 'vxlan', 'CDN', 'rdma_qp', 'rdma_mr', 'rdma_resgrp']
            out_list = output.split("---")
            for out_block in out_list[1:]:
                intf_tmp_list = []
                for attr in attr_list:
                    value = re.search(attr+': ([^\r\n.$]+)', out_block)
                    if value != None:
                        value = value.group(1)
                    intf_tmp_list.append(value)
                self.eth_int_details.append(HostEthInt(intf_tmp_list[0], intf_tmp_list[1], intf_tmp_list[2],
                                                  intf_tmp_list[3], intf_tmp_list[4], intf_tmp_list[5],
                                                  intf_tmp_list[6], intf_tmp_list[7], intf_tmp_list[8],
                                                  intf_tmp_list[9], intf_tmp_list[10], intf_tmp_list[11],
                                                  intf_tmp_list[12], intf_tmp_list[13], intf_tmp_list[14],
                                                  intf_tmp_list[15], intf_tmp_list[16], intf_tmp_list[17],
                                                  intf_tmp_list[18], intf_tmp_list[19], intf_tmp_list[20],
                                                  intf_tmp_list[21], intf_tmp_list[22], intf_tmp_list[23],
                                                  intf_tmp_list[24]))
            return self.eth_int_details
        except:
            dump_error_in_lib()
            return False
    def host_cdn_mac_dict(self, host_handle, cmd):
        '''
        procedure to get MAC:CDN dictionary from Host
        Parameter:
            host_handle: obj containing host handle
            cmd: command to run on host       
        Return:
            dictionary containing mac:cdn from host
            False : FAILURE
        Author : jchanda
        '''
        host_cdn_dict = {}
        output = host_handle.execute_cmd(cmd, wait_time=10)
        out_list = output.split("BIOS device")
        for out_block in out_list[1:]:
            if 'sysfs Label' in out_block:
                for line in out_block.splitlines():
                    if 'Permanent MAC' in line:
                        key = line.split('Permanent MAC:')[1].replace(' ', '')
                    if 'sysfs Label' in line:
                        host_cdn_dict[key] = line.split(':')[1].replace(' ', '')
        logger.info('Form host mac:cdn dict is: ' + str(host_cdn_dict))
        return host_cdn_dict
    def cimc_cdn_mac_dict(self, adapter_slot):
        '''
        procedure to get MAC:CDN dictionary from CIMC CLI
        Parameter:
            slot_no: adapter slot no.       
        Return:
            dictionary containing mac:cdn from cimc cli
            False : FAILURE
        Author : jchanda
        '''        
        eth_int_details = self.get_host_eth_int_details(adapter_slot)
        cimc_cdn_dict = {}
        for interface in eth_int_details:
            if interface.CDN is not None:
                cimc_cdn_dict[interface.mac_addr.replace(' ', '')] = interface.CDN.replace(' ', '')
        logger.info('From CIMC mac:cdn dict is: ' + str(cimc_cdn_dict))
        if len(cimc_cdn_dict) == 0:
            return False
        else:
            return cimc_cdn_dict
    def powercycle_and_verify_cdn_on_cimc_and_host(self, slot_no):
        '''
        procedure to verify cdn details from CIMC and Host side
        Parameter:
            slot_no: adapter slot no.        
        Return:
            True: Success
            False : FAILURE
        Author : jchanda
        '''        
        res = self.cimc_obj.power_cycle_host()
        if res is not True:
            logger.error('Failed to power cycle the host')
        time.sleep(60)
        # verify host is up
        host_detail_obj = self.config.host_info[0].host_detail
        host_ip = host_detail_obj.os_host_name
        res_host_up = self.cimc_obj.verify_host_up(hostname=host_ip)
        if res_host_up:
            logger.info('Host rebooted successfully after creating new vNIC')
        else :
            logger.warn('Issue with host reboot')
        '''Get the interface details in Dictionary ['mac_addr' : 'cdn_name']'''
        cimc_dict = self.cimc_cdn_mac_dict(slot_no)
        logger.info('vNIC interface mac:cdn details from CIMC: ' + str(cimc_dict))
        if cimc_dict is False:
            logger.warn('CIMC CDN mac list is empty')
            return False
        host_user = host_detail_obj.os_login
        host_passwd = host_detail_obj.os_password
        ntw_list = self.config.host_info[0].nw_intf_list
        for intf in ntw_list:
            if intf.is_mgmt_intf == 'yes':
                logger.info('Host Managment IP is: ' + intf.ip_address)
                host_ip = intf.ip_address
        '''connect to host and get CDN details'''
        host_handle = LinuxUtils(host_ip, host_user, host_passwd)
        host_handle.connect()
        host_dict = self.host_cdn_mac_dict(host_handle, 'biosdevname -d')
        logger.info('vNIC interface mac:cdn details from Host: ' + str(host_dict))
        match = True
        for key in cimc_dict.keys():
            if key in host_dict.keys():
                if cimc_dict[key] != host_dict[key]:
                    logger.error('After OS boot, CDN name set from CIMC CLI and Host are not same')
                    logger.error('CDN name from CIMC:' +cimc_dict[key] + 'Host CDN: ' + host_dict[key])
                    match = False
                else:
                    logger.info('After OS boot, CDN name set from CIMC CLI and Host are remains same')
                    logger.info('Configure CDN name from CIMC: ' +cimc_dict[key] + ' Host CDN: ' + host_dict[key])
        if match is True:
            return True
        else:
            return False
    def powercycle_and_verify_cdn_on_windows(self, slot_no):
        '''
        procedure to verify cdn details from CIMC and Host side for Windows OS
        Parameter:
            slot_no: adapter slot no.        
        Return:
            True: Success
            False : FAILURE
        Author : jchanda
        '''         
        res = self.cimc_obj.power_cycle_host()
        if res is not True:
            logger.error('Failed to power cycle the host')
        time.sleep(60)
        ntw_list = self.config.host_info[0].nw_intf_list
        for intf in ntw_list:
            if intf.is_mgmt_intf == 'yes':
                logger.info('Host Managment IP is: ' + intf.ip_address)
                host_ip = intf.ip_address
        '''verify host is up'''
        res_host_up = self.cimc_obj.verify_host_up(hostname=host_ip, wait_time=500)
        if res_host_up:
            logger.info('Host rebooted successfully')
        else :
            logger.warn('Issue with host reboot')
        '''Get the interface details in Dictionary ['mac_addr' : 'cdn_name']'''
        cimc_dict = self.cimc_cdn_mac_dict(slot_no)
        logger.info('vNIC interface mac:cdn details from CIMC: ' + str(cimc_dict))

        host_detail_obj = self.config.host_info[0].host_detail
        host_user = host_detail_obj.os_login
        host_passwd = host_detail_obj.os_password
        '''connect to host and get CDN details'''
        logger.info('Connecting to Windows using IP:{}, user:{}, password:{}'.format(host_ip, host_user, host_passwd))
        host_handle = WindowsUtil(host_ip, host_user, host_passwd)
        data = host_handle.execute_cmd('netsh interface show interface', wait_time=6)
        logger.info('command output from windows host: ' + str(data))
        cdn_list = []
        for line in data.splitlines():
            if re.search('Enabled', str(line), re.I):
                reg = re.search(r'(\w+)\s+(\w+)\s+(\w+)\s+([^\r\n\']+)', str(line))
                cdn_list.append(reg.group(4))
        '''Validation part'''
        match = True
        for key in cimc_dict.keys():
            if cimc_dict[key] in cdn_list:
                logger.info('Successfully verified that cdn name \'{}\' found on host'.format(cimc_dict[key]))
            else:
                logger.error('Failed to verify that cdn name \'{}\' found on host'.format(cimc_dict[key]))
                match = False
        if match is True:
            return True
        else:
            return False