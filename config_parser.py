'''
Created on Jan 10, 2017
@author: suremoore
'''
'''
Created on Jan 10, 2017
@author: suremoore
'''
import configparser
import logging
import os
from tb_data import *


logger = logging.getLogger(__name__)

__author__ = 'Suren Kumar Moorthy <suremoor@cisco.com>'
__copyright__ = 'Copyright 2016, Cisco Systems'
__email__ = 'suremoor@cisco.com'
__date__ = 'Sep 29,2016'
__version__ = 1.0


class ConfigParser():
    '''
        Class for Config Parser
    '''

    def __init__(self, testbed=None):
        self.config = configparser.ConfigParser()
        if testbed is not None:
            self.testbed = testbed
            self.testbedconfigdetails = TestbedDetails()
            self.commonconfigdetails = CommonDetails()
            self.processorconfigdetails = ProcessorDetails()
        else:
            self.commonconfigdetails = CommonDetails()
            self.processorconfigdetails = ProcessorDetails()

    def get_config_parser_obj(self):
        return self.config

    def load_config(self, config_file):
        '''
        Load config based on the file type

        Return:
            SUCCESS - loaded object
            FAILED - None
        '''
        try:
            file_name = os.environ["GITMAIN"] + \
                "/config/" + config_file + ".cfg"
            cfg_file_path = file_name
            logger.info('Config file Path : %s' % cfg_file_path)
            self.config._interpolation = configparser.ExtendedInterpolation()
            self.config.read(cfg_file_path)
            return self
        except Exception as inst:
            logger.error("Caught exception while reading the config file")
            logger.error(type(inst))
            logger.error(inst.args)
            return None

    def get_bios_config(self):
        '''
        Load bios config based on the testbed name

        Return:
            SUCCESS - loaded object
            FAILED - None
        '''
        # try:
        # config_file = self.testbed+"-bios"
        # except Exception as inst:
        # logger.error("Caught exception while reading the config file")
        # logger.error(type(inst))
        # logger.error(inst.args)
        # return None

    def get_net_config(self):
        '''
        Load net config based on the testbed name

        Return:
            SUCCESS - loaded object
            FAILED - None
        '''
        try:
            config_file = self.testbed + "-net"
            if self.load_config(config_file) is None:
                return None
            else:
                return self.load_config(config_file)
        except Exception as inst:
            logger.error("Caught exception while reading the config file")
            logger.error(type(inst))
            logger.error(inst.args)
            return None

    def load_testbed_config(self):
        '''
        Load basic config based on the testbed name
        Return:
            SUCCESS - loaded object
            FAILED - None
        '''
        try:
            config_file = self.testbed
            if self.load_config(config_file) is None:
                return None
            else:
                bmc_mgmt_ip = self.config.get('MgmtEndPoint', 'bmc_mgmt_ip')
                bmc_net_mask = self.config.get('MgmtEndPoint', 'bmc_net_mask')
                bmc_gway = self.config.get('MgmtEndPoint', 'bmc_gway')
                bmc_login = self.config.get('MgmtEndPoint', 'bmc_login')
                bmc_password = self.config.get('MgmtEndPoint', 'bmc_password')
                bmc_prompt = self.config.get('MgmtEndPoint', 'bmc_prompt')
                bmc_mac_addr = self.config.get('MgmtEndPoint', 'bmc_mac_addr')
                serial_console = self.config.get(
                    'MgmtEndPoint', 'serial_console')
                platform = self.config.get('MgmtEndPoint', 'platform')
                platform_series = self.config.get('MgmtEndPoint', 'platform_series')
                self.testbedconfigdetails.mgmtdetail = MgmtDetails(bmc_mgmt_ip, bmc_net_mask,
                                                                   bmc_gway, bmc_login,
                                                                   bmc_password, bmc_prompt,
                                                                   bmc_mac_addr, serial_console,
                                                                   platform, platform_series)
                bmc_list = self.config.get('MgmtEndPoint', 'bmc_list')

                if 'BmcDetail' in bmc_list:
                    for bmc_det in bmc_list.split(","):
                        bmc_info_obj = BmcInfo()

                        serial_console_bmc = self.config.get(
                            bmc_det, 'serial_console_bmc')
                        bmc_info_obj.bmc_detail = BmcDetails(
                            serial_console_bmc)
                        bmc_svr_ip = self.config.get(
                            serial_console_bmc, 'bmc_svr_ip')
                        bmc_svr_port = self.config.get(
                            serial_console_bmc, 'bmc_svr_port')
                        bmc_svr_type = self.config.get(
                            serial_console_bmc, 'bmc_svr_type')
                        bmc_login_name = self.config.get(
                            serial_console_bmc, 'bmc_login_name')
                        bmc_login_pwd = self.config.get(
                            serial_console_bmc, 'bmc_login_pwd')
                        bmc_info_obj.bmc_serial = SerialDetails(bmc_svr_ip, bmc_svr_port,
                                                                bmc_svr_type, bmc_login_name,
                                                                bmc_login_pwd)
                        self.testbedconfigdetails.bmc_info.append(bmc_info_obj)
                else:
                    bmc_info_obj = BmcInfo()
                    serial_console_bmc = serial_console
                    bmc_info_obj.bmc_detail = BmcDetails(serial_console_bmc)
                    bmc_svr_ip = self.config.get(
                        serial_console_bmc, 'bmc_svr_ip')
                    bmc_svr_port = self.config.get(
                        serial_console_bmc, 'bmc_svr_port')
                    bmc_svr_type = self.config.get(
                        serial_console_bmc, 'bmc_svr_type')
                    bmc_login_name = self.config.get(
                        serial_console_bmc, 'bmc_login_name')
                    bmc_login_pwd = self.config.get(
                        serial_console_bmc, 'bmc_login_pwd')
                    bmc_info_obj.bmc_serial = SerialDetails(bmc_svr_ip, bmc_svr_port,
                                                            bmc_svr_type, bmc_login_name,
                                                            bmc_login_pwd)
                    self.testbedconfigdetails.bmc_info.append(bmc_info_obj)
                host_list = self.config.get('MgmtEndPoint', 'host_list')
                for host_det in host_list.split(","):
                    host_info_obj = HostInfo()
                    os_type = self.config.get(host_det, 'os_type')
                    os_login = self.config.get(host_det, 'os_login')
                    os_password = self.config.get(host_det, 'os_password')
                    os_host_name = self.config.get(host_det, 'os_host_name')

                    serial_console_host = self.config.get(
                        host_det, 'serial_console_host')
                    host_info_obj.host_detail = HostDetails(os_type, os_login, os_password,
                                                            os_host_name, serial_console_host)
                    host_svr_ip = self.config.get(
                        serial_console_host, 'host_svr_ip')
                    host_svr_port = self.config.get(
                        serial_console_host, 'host_svr_port')
                    host_svr_type = self.config.get(
                        serial_console_host, 'host_svr_type')
                    host_login_name = self.config.get(
                        serial_console_host, 'host_login_name')
                    host_login_pwd = self.config.get(
                        serial_console_host, 'host_login_pwd')
                    host_info_obj.host_serial = SerialDetails(host_svr_ip, host_svr_port,
                                                              host_svr_type, host_login_name,
                                                              host_login_pwd)
                    net_list = self.config.get(host_det, 'net_list')
                    for net_int in net_list.split(","):
                        ip_address = self.config.get(net_int, 'ip_address')
                        mac_address = self.config.get(net_int, 'mac_address')
                        net_mask = self.config.get(net_int, 'net_mask')
                        gate_way = self.config.get(net_int, 'gate_way')
                        data_rate = self.config.get(net_int, 'data_rate')
                        name = self.config.get(net_int, 'name')
                        is_mgmt_intf = self.config.get(net_int, 'is_mgmt_intf')
                        host_info_obj.nw_intf_list.append(HostNetDetails(ip_address, mac_address,
                                                                         net_mask, gate_way,
                                                                         data_rate, name,
                                                                         is_mgmt_intf))
                    self.testbedconfigdetails.host_info.append(host_info_obj)
                apc_ip = self.config.get('ApcDetails', 'apc_ip')
                port_list = self.config.get('ApcDetails', 'port_list')
                model = self.config.get('ApcDetails', 'model')

                self.testbedconfigdetails.apcdetails = APCDetails(
                    apc_ip, port_list, model)
                try:
                    dimm_list = self.config.get('InventoryDetails', 'dimm_pid')
                    self.testbedconfigdetails.dimm_pid = dimm_list.split(",")
                except:
                    self.testbedconfigdetails.dimm_pid = None
                '''VIC Inventory details '''
                vic_list = None
                try:
                    vic_list = self.config.get('InventoryDetails', 'vic_list')
                except:
                    logger.warning('VIC inventory is not configured on this testbed config file')
                if vic_list is not None:
                    for vic in vic_list.split(","):
                        slot_number = self.config.get(vic, 'slot_number')
                        self.testbedconfigdetails.inventory_detail.append(
                            InventoryDetails(slot_number))
                '''PCI Adapter Details '''
                pci_list = None
                try:
                    pci_list = self.config.get('InventoryDetails', 'pci_adapter_details')
                except:
                    logger.warning('PCI Adapter inventory is not configured on this testbed config file')
                if pci_list is not None:
                    for pci in pci_list.split(","):
                        slot = self.config.get(pci, 'slot')
                        product_name = self.config.get(pci, 'product_name')
                        self.testbedconfigdetails.pci_adapter_detail.append(
                            PcieInventoryDetails(slot, product_name))
                '''L2 Boot device details'''
                boot_device_list = None
                boot_device_dict = {}
                try:
                    boot_device_list = self.config.get('BootDeviceDetail', 'boot_device_types')
                except:
                    logger.warning('No L2 boot order device have been configured')
                if boot_device_list is not None:
                    boot_device_list = boot_device_list.split(',')
                    logger.info('List of boot devices: ' + str(boot_device_list))
                    for boot_device in boot_device_list:
                        try:
                            boot_device_dict[boot_device] = self.config[boot_device]
                        except configparser.NoSectionError:
                            logger.warning('No section name called:' + boot_device)
                        except configparser.NoOptionError:
                            logger.warning('No option name for boot device: ' + boot_device)
                        except KeyError:
                            logger.warning('Key error while populating L2 boot config data')
                self.testbedconfigdetails.boot_device_detail = boot_device_dict
                '''Basic Boot device details'''
                basic_boot_device_list = None
                basic_boot_device_dict = {}
                try:
                    basic_boot_device_list = self.config.get('BasicBootDeviceDetail', 'boot_device_types')
                    print(basic_boot_device_list)
                except:
                    logger.warning('No Basic boot order device have been configured')
                if basic_boot_device_list is not None:
                    boot_device_list = basic_boot_device_list.split(',')
                    logger.info('List of Basic boot devices: ' + str(boot_device_list))
                    for boot_device in boot_device_list:
                        try:
                            basic_boot_device_dict[boot_device] = self.config[boot_device]
                        except configparser.NoSectionError:
                            logger.warning('No section name called:' + boot_device)
                        except configparser.NoOptionError:
                            logger.warning('No option name for %s boot device' % (boot_device))
                        except KeyError:
                            logger.warning('Key error while populating %s boot device' % (boot_device))
                self.testbedconfigdetails.basic_boot_device_detail = basic_boot_device_dict
                '''BIOS Tokens details'''
                bios_token_list = None
                bios_token_dict = {}
                try:
                    bios_token_list = self.config.get('BiosTokenDetails', 'bios_token_list')
                except:
                    logger.warning('No L2 boot order device have been configured')
                if bios_token_list is not None:
                    bios_token_list = bios_token_list.split(',')
                    logger.info('List of BIOS Tokens are: ' + str(bios_token_list))
                    for bios_token in bios_token_list:
                        try:
                            bios_token_dict[bios_token] = self.config[bios_token]
                        except configparser.NoSectionError:
                            logger.warning('No section name called:' + bios_token)
                        except configparser.NoOptionError:
                            logger.warning('No option name for boot device: ' + bios_token)
                        except KeyError:
                            logger.warning('Key error while populating BIOS tokens config data')
                self.testbedconfigdetails.bios_token_detail = bios_token_dict
            return self.testbedconfigdetails

        except Exception as inst:
            logger.error("Caught exception while reading the config file")
            logger.error(type(inst))
            logger.error(inst.args)
            return None

    def load_common_config(self, location="BLR"):
        '''
        Load basic config based on the testbed name
        Return:
            SUCCESS - loads object
            FAILED - None
        '''
        try:
            config_file = "config" if location == "BLR" else "config_sjc"
            if self.load_config(config_file) is None:
                return None
            else:
                nfs_list = self.config.get('share_constants', 'nfsServer')
                print(nfs_list)
                for nfs_detail in nfs_list.split(","):
                    nfs_server_ip = self.config.get(nfs_detail, 'nfsServerIp')
                    nfs_share_dir = self.config.get(nfs_detail, 'nfsShareDir')

                    nfs_svmedia_dir = self.config.get(
                        nfs_detail, 'nfsSvmediaDir')
                    nfs_user = self.config.get(nfs_detail, 'nfsUser')
                    nfs_passwd = self.config.get(nfs_detail, 'nfsPasswd')
                    self.commonconfigdetails.nfs_share_list.append(
                        NfsShareDetails(nfs_server_ip, nfs_share_dir,
                                        nfs_svmedia_dir, nfs_user,
                                        nfs_passwd))
                tftp_server_ip = self.config.get(
                    'tftpserver', 'tftp_server_ip')
                tftp_user = self.config.get('tftpserver', 'tftp_user')
                tftp_password = self.config.get('tftpserver', 'tftp_password')
                tftp_root_path = self.config.get(
                    'tftpserver', 'tftp_root_path')
                self.commonconfigdetails.tftp_share = TftpShareDetails(
                    tftp_server_ip, tftp_user, tftp_password, tftp_root_path)
                return self.commonconfigdetails
        except Exception as inst:
            logger.error("Caught exception while reading the config file")
            logger.error(type(inst))
            logger.error(inst.args)
            return None

    def load_processor_config(self, model):
        '''
        Load proccesor config
        Return:
            SUCEESS - load object
            FAILED - None
        '''
        try:
            config_file = 'processor'
            if self.load_config(config_file) is None:
                return None
            else:
                name = self.config.get(model, 'name')
                manufacturer = self.config.get(model, 'manufacturer')
                family = self.config.get(model, 'family')
                thread_count = self.config.get(model, 'thread_count')
                core_count = self.config.get(model, 'core_count')
                version = self.config.get(model, 'version')
                current_speed = self.config.get(model, 'current_speed')
                signature = self.config.get(model, 'signature')
                cpu_status = self.config.get(model, 'cpu_status')
                pid = self.config.get(model, 'pid')
                processor_upgrade = self.config.get(model, 'processor_upgrade')
                smbios_version = self.config.get(model, 'smbios_version')
                cpu_lowest_freq = self.config.get(model, 'cpu_lowest_freq')
                cpu_expected_freq = self.config.get(model, 'cpu_expected_freq')
                cpu_onecore_turbo = self.config.get(model, 'cpu_onecore_turbo')
                cpu_maxcore_turbo = self.config.get(model, 'cpu_maxcore_turbo')
                turbo_support = self.config.get(model, 'turbo_support')
                l1_cache = self.config.get(model, 'l1_cache')
                l1_cache_p = self.config.get(model, 'l1_cache_p')
                l2_cache = self.config.get(model, 'l2_cache')
                l3_cache = self.config.get(model, 'l3_cache')
                self.processorconfigdetails.proceesor_details = ProcessorInfo(name, manufacturer,
                                                                              family, thread_count,
                                                                              core_count, version,
                                                                              current_speed,
                                                                              signature,
                                                                              cpu_status, pid,
                                                                              processor_upgrade,
                                                                              smbios_version,
                                                                              cpu_lowest_freq,
                                                                              cpu_expected_freq,
                                                                              cpu_onecore_turbo,
                                                                              cpu_maxcore_turbo,
                                                                              turbo_support,
                                                                              l1_cache, l1_cache_p,
                                                                              l2_cache, l3_cache)
            return self.processorconfigdetails
        except Exception as inst:
            logger.error("Caught exception while reading the config file")
            logger.error(type(inst))
            logger.error(inst.args)
            return None
