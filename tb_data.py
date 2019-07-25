'''
Module to load all testbed related data in object
'''
import logging

logger = logging.getLogger(__name__)


__author__ = 'Suren Kumar Moorthy <suremoor@cisco.com>'
__copyright__ = 'Copyright 2016, Cisco Systems'
__email__ = 'suremoor@cisco.com'
__date__ = 'Oct 11,2016'
__version__ = 1.0


class MgmtDetails():
    '''
    Management class object which contains management details
    '''

    def __init__(self, bmc_mgmt_ip, bmc_net_mask,
                 bmc_gway, bmc_login, bmc_password,
                 bmc_prompt, bmc_mac_addr,
                 serial_console, platform, platform_series):
        if bmc_mgmt_ip:
            self.bmc_mgmt_ip = bmc_mgmt_ip
        else:
            logger.error("bmcMgmtIp is empty")
            self.bmc_mgmt_ip = None
        self.bmc_net_mask = bmc_net_mask
        self.bmc_gway = bmc_gway
        self.bmc_login = bmc_login
        self.bmc_password = bmc_password
        self.bmc_prompt = bmc_prompt
        self.bmc_mac_addr = bmc_mac_addr
        self.serial_console = serial_console
        self.platform = platform
        self.platform_series = platform_series


class HostDetails():
    '''
    HostDetails class object which contains HostDetails details
    '''

    def __init__(self, os_type, os_login, os_password, os_host_name, serial_console):
        self.os_type = os_type
        self.os_login = os_login
        self.os_password = os_password
        self.os_host_name = os_host_name
        self.serial_console = serial_console


class BmcDetails():
    '''
    BMC Details class object which contains BMC details
    '''

    def __init__(self, serial_console):
        self.serial_console = serial_console


class SerialDetails():
    '''
    Serial Details class to load serial objects for both host and bmc
    '''

    def __init__(self, svr_ip, svr_port, svr_type, login_name, login_pwd):
        self.svr_ip = svr_ip
        self.svr_port = svr_port
        self.svr_type = svr_type
        self.login_name = login_name
        self.login_pwd = login_pwd


class APCDetails():
    '''
    Class for APC details
    '''

    def __init__(self, apc_ip, port_list, model):
        self.apc_ip = apc_ip
        self.port_list = port_list
        self.model = model


class HostNetDetails():
    '''
    Class for Host network details
    '''

    def __init__(self, ip_address, mac_address, net_mask, df_gway, data_rate, name, is_mgmt_intf):
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.net_mask = net_mask
        self.df_gway = df_gway
        self.data_rate = data_rate
        self.name = name
        self.is_mgmt_intf = is_mgmt_intf


class NfsShareDetails():
    '''
    Class for NFS share details
    '''

    def __init__(self, nfs_server_ip, nfs_share_dir, nfs_svmedia_dir, nfs_user, nfs_passwd):
        print(nfs_server_ip)
        self.nfs_server_ip = nfs_server_ip
        self.nfs_share_dir = nfs_share_dir
        self.nfs_svmedia_dir = nfs_svmedia_dir
        self.nfs_user = nfs_user
        self.nfs_passwd = nfs_passwd


class TftpShareDetails():
    '''
    Class for Tftp share
    '''

    def __init__(self, tftp_server_ip, tftp_user, tftp_password, tftp_root_path):
        print(tftp_server_ip)
        self.tftp_server_ip = tftp_server_ip
        self.tftp_user = tftp_user
        self.tftp_password = tftp_password
        self.tftp_root_path = tftp_root_path


class InventoryDetails():
    '''
    Class for Inventory Details
    '''

    def __init__(self, slot_number):
        self.slot_number = slot_number


class PcieInventoryDetails():
    '''
    Class for PCIE Inventory Details
    '''

    def __init__(self, slot, product_name):
        self.slot = slot
        self.product_name = product_name


class ProcessorInfo():
    '''
    Class for Processor Information
    '''

    def __init__(self, name, manufacturer, family, thread_count, core_count, version,
                 current_speed, signature, cpu_status, pid, processor_upgrade, smbios_version,
                 cpu_lowest_freq, cpu_expected_freq, cpu_onecore_turbo, cpu_maxcore_turbo,
                 turbo_support, l1_cache, l1_cache_p, l2_cache, l3_cache):

        self.name = name
        self.manufacturer = manufacturer
        self.family = family
        self.thread_count = thread_count
        self.core_count = core_count
        self.version = version
        self.current_speed = current_speed
        self.signature = signature
        self.cpu_status = cpu_status
        self.pid = pid
        self.processor_upgrade = processor_upgrade
        self.smbios_version = smbios_version
        self.cpu_lowest_freq = cpu_lowest_freq
        self.cpu_expected_freq = cpu_expected_freq
        self.cpu_onecore_turbo = cpu_onecore_turbo
        self.cpu_maxcore_turbo = cpu_maxcore_turbo
        self.turbo_support = turbo_support
        self.l1_cache = l1_cache
        self.l1_cache_p = l1_cache_p
        self.l2_cache = l2_cache
        self.l3_cache = l3_cache


class TestbedDetails():
    '''
    Testbed Details class with init object variables of testbed related objects
    '''

    def __init__(self):
        self.mgmtdetail = None
        self.bmc_info = []
        self.host_info = []
        self.inventory_detail = []
        self.pci_adapter_detail = []
        self.boot_device_detail = {}
        self.basic_boot_device_detail = {}
        self.bios_token_detail = {}
        self.dimm_pid = []


class HostInfo():
    '''
    Host Information class with init object variables of Host related objects
    '''

    def __init__(self):
        self.host_detail = None
        self.host_serial = None
        self.nw_intf_list = []


class BmcInfo():
    '''
    BMC Information class with init object variables of BMC related objects
    '''

    def __init__(self):
        self.bmc_detail = None
        self.bmc_serial = None


class CommonDetails():
    '''
    Commont Information class with init object variables of Common details
    '''

    def __init__(self):
        self.nfs_share_list = []
        self.tftp_share = None


class ProcessorDetails():
    '''
    Processor Information class with init object variables of Processor related objects
    '''

    def __init__(self):
        self.proceesor_details = None
