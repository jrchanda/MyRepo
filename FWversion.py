import logging
import subprocess
from asyncio.log import logger
import re
from ats import aetest
from ats import easypy
from config_parser import ConfigParser
from common_test import Setup, Cleanup
from linux_utils import LinuxUtils
from exp_imp_utils import ExpImpUtils
from firmware_utils import FirmwareUtils
from smbios_lib import SmbiosLib
#from SystemDetailsCollector_lib import SystemDetailsCapture
#import linux_utils
logger = logging.getLogger(__name__)


class CommonSetup(Setup):
    '''
    Common Setup section which connects to CIMC
    '''
    @aetest.subsection
    def connect(self, testscript, testbed_name):
        super(CommonSetup, self).connect(testscript, testbed_name)


class FwVersion(aetest.Testcase):

    def fw_cimc_cli(self, cimc_util_obj):
        mgmt_handle = cimc_util_obj.handle
        output = mgmt_handle.execute_cmd_list(
            'top', 'scope chassis', 'show pci-adapter detail')
        fw_id = []
        logger.info("Output......" + output)
        for block in output.split("---")[1:]:
            firmware = re.search('fw-version:*\s+([^\r\n]+)', block).group(1)
            fw_id.append(firmware)
            logger.info("Firmware info ...." + firmware)
        return fw_id

    def product_cimc(self, cimc_util_obj):

        mgmt_handle = cimc_util_obj.handle
        output = mgmt_handle.execute_cmd_list(
            'top', 'scope chassis', 'show pci-adapter detail')
        product_name = []
        for block in output.split("---")[1:]:
            product = re.search('product-name:*\s+([^\r\n]+)', block).group(1)
            product_name.append(product)
            logger.info("Product name  info...." + str(product_name))
        return product_name

    def slot_interface(self, cimc_util_obj):

        mgmt_handle = cimc_util_obj.handle
        output = mgmt_handle.execute_cmd_list(
            'top', 'scope chassis', 'show pci-adapter detail')
        interface_id = []
        for block in output.split("---")[1:]:
            slot = re.search('slot:*\s+([^\r\n]+)', block).group(1)
            interface_id.append(slot)
            logger.info("Interface info..." + str(interface_id))
        return interface_id

    def fw_linux(self, cimc_util_obj, host_os_ip):

        cimc_util_obj.verify_host_up(
            hostname=host_os_ip, wait_for_ping_fail=False, wait_time=600)
        os_handle = cimc_util_obj.host_handle
        os_handle.connect()
        output = os_handle.execute_cmd('dmidecode -t202')
        newdict = {}
        rege = r'Strings\:\s*(\w[^\n\r]+)\s*([^\n\r]+)\s*([^\n\r]+)'
        for (x, y, z) in re.findall(rege, output):
            newdict[x] = z
        logger.info("New Dict")
        logger.info(newdict)
        return newdict

    def efi_mode(self, cimc_util_obj, host_os_ip):
        mgmt_handle = cimc_util_obj.handle
        mgmt_handle.execute_cmd_list(
            'scope bios', 'set boot-mode Uefi', 'commit', 'y')
        cimc_util_obj.verify_host_up(
            hostname=host_os_ip, wait_for_ping_fail=False, wait_time=600)

    def legacy_mode(self, cimc_util_obj, host_os_ip):
        mgmt_handle = cimc_util_obj.handle
        mgmt_handle.execute_cmd_list(
            'exit', 'scope bios', 'set boot-mode Legacy', 'commit', 'y')
        cimc_util_obj.verify_host_up(
            hostname=host_os_ip, wait_for_ping_fail=False, wait_time=600)

    @aetest.test
    def verify_firmware_efi(self, cimc_util_obj, config):
        smbios_obj = SmbiosLib()
        host_os_ip = smbios_obj.get_host_mgmt_ip(config)
        efi_boot = self.efi_mode(cimc_util_obj, host_os_ip)
        bmc_fw_list = self.fw_cimc_cli(cimc_util_obj)
        interface_list = self.slot_interface(cimc_util_obj)
        product_list = self.product_cimc(cimc_util_obj)
        os_fw_list = self.fw_linux(cimc_util_obj, host_os_ip)
        logger.info("cimc fw info......." + str(bmc_fw_list))
        logger.info("OS fw info......." + str(os_fw_list))
        fw_interface_list = len(bmc_fw_list)
        pci_adapter_list = len(product_list)
        slot_list = len(interface_list)
        logger.info("Firmware info......." + str(fw_interface_list))
        logger.info("PCI adapter info......." + str(pci_adapter_list))
        logger.info("SLOT-ID info......" + str(slot_list))

        if fw_interface_list == pci_adapter_list == slot_list:
            logger.info("PCI adapter and Fw version and Slot ID is Matched ")
        else:
            self.failed(
                "PCI adapter and Fw Version and Slot ID is NOT matched")
            return False

        cimc_fw_list = {}
        for (i, j) in zip(product_list, bmc_fw_list):
            cimc_fw_list[i] = j
            logger.info("cimc fw list ...." + str(cimc_fw_list))

        for k, v in cimc_fw_list.items():
            if v != 'N/A':
                logger.info("Firmware version Passed in cimc:" + str(k))
            else:
                self.failed(
                    "Firmware version is Not Displayed in cimc :" + str(k))

        for k, v in os_fw_list.items():
            if v != 'N/A':
                logger.info("Firmware version passed in OS :" + str(k))
            else:
                logger.info("Firmware version Not displayed in OS:" + str(k))

        for items in os_fw_list.items():
            if items in cimc_fw_list.items():
                logger.info(
                    "Firmware Comparison between cimc and OS PASSED:" + str(items))
            else:
                logger.info(
                    "Firmware Comparison between cimc and OS FAILED:" + str(items))

    @aetest.test
    def HuuCompare(self, cimc_util_obj, testbed_name, config):
        config_parser = ConfigParser(testbed_name)
        config_parser.load_config(testbed_name)
        mgmt_handle = cimc_util_obj.handle
        output = mgmt_handle.execute_cmd_list(
            'top', 'scope chassis', 'show pci-adapter detail')
        logger.info(output)
        pci_card_details_cimc = {}
        pci_card_details_toc = {}
        pci_card = re.findall(r'product-name:*\s+([^\r\n]+)', output)
        pci_card_version = re.findall(r'fw-version:*\s+([^\r\n]+)', output)
        for (card, version) in zip(pci_card, pci_card_version):
            pci_card_details_cimc[card] = version
        #cmd_str = 'cat /data/home/kgeevane/grit_code/rackauto/tests/TOC_DELNORTE1.xml'
        #toc_out = subprocess.check_output(cmd_str, shell=True, stderr=subprocess.STDOUT).decode(encoding='utf_8', errors='strict')
        toc_out = cimc_util_obj.get_release_note_content(config)
        for pci_card in pci_card_details_cimc.keys():
            card_name_toc = config_parser.config.get(
                'PciAdapterFWVersion', pci_card)
            logger.info(card_name_toc)
            regex = r'component\s*name\=\"' + \
                card_name_toc + r'\".*?version\s*\=\"(.*?)\"'
            # Getting version from TOC file.
            pci_card_details_toc[pci_card] = re.search(regex, toc_out).group(1)
        logger.info("######## PCI CARD CIMC##############")
        logger.info(pci_card_details_cimc)
        logger.info("######## PCI CARD TOC ##############")
        logger.info(pci_card_details_toc)
        logger.info("####################################")
        pass_flag = 1
        for pci_card_cimc in pci_card_details_cimc.keys():
            if pci_card_details_cimc[pci_card_cimc] in pci_card_details_toc[pci_card_cimc]:
                logger.info(
                    "PCI card " + pci_card_details_cimc[pci_card_cimc] + 
                     " version matches with TOC file")
            else:
                logger.error(
                    "PCI card " + pci_card_details_cimc[pci_card_cimc] +
                     " version not matches with TOC file")
                pass_flag = 0
        if pass_flag == 1:
            self.passed(
                "Successfully verified all the cards versions with TOC xml")
        else:
            self.failed("Card verification with TOC xml got failed")
        #mgip = config_parser.config.get('PciAdapterFWVersion', 'UCS VIC 1227 10Gbps 2 port CNA SFP+')


    @aetest.test
    def verify_firmware_legacy(self, cimc_util_obj, config):
        smbios_obj = SmbiosLib()
        host_os_ip = smbios_obj.get_host_mgmt_ip(config)
        legacy_boot = self.legacy_mode(cimc_util_obj, host_os_ip)
        bmc_fw_list = self.fw_cimc_cli(cimc_util_obj)
        interface_list = self.slot_interface(cimc_util_obj)
        product_list = self.product_cimc(cimc_util_obj)
        os_fw_list = self.fw_linux(cimc_util_obj, host_os_ip)
        logger.info("cimc fw info......." + str(bmc_fw_list))
        logger.info("OS fw info......." + str(os_fw_list))
        fw_interface_list = len(bmc_fw_list)
        pci_adapter_list = len(product_list)
        slot_list = len(interface_list)
        logger.info("Firmware info......." + str(fw_interface_list))
        logger.info("PCI adapter info......." + str(pci_adapter_list))
        logger.info("SLOT-ID info......" + str(slot_list))

        if fw_interface_list == pci_adapter_list == slot_list:
            logger.info("PCI adapter and Fw version and Slot ID is Matched ")
        else:
            self.failed(
                "PCI adapter and Fw Version and Slot ID is NOT matched")
            return False

        cimc_fw_list = {}
        for (i, j) in zip(product_list, bmc_fw_list):
            cimc_fw_list[i] = j
            logger.info("cimc fw list ...." + str(cimc_fw_list))

        for k, v in cimc_fw_list.items():
            if v != 'N/A':
                logger.info("Firmware version Passed in cimc:" + str(k))
            else:
                self.failed(
                    "Firmware version is Not Displayed in cimc :" + str(k))

        for k, v in os_fw_list.items():
            if v != 'N/A':
                logger.info("Firmware version passed in OS :" + str(k))
            else:
                logger.info("Firmware version Not displayed in OS:" + str(k))

        for items in os_fw_list.items():
            if items in cimc_fw_list.items():
                logger.info(
                    "Firmware Comparison between cimc and OS PASSED:" + str(items))
            else:
                logger.info(
                    "Firmware Comparison between cimc and OS FAILED:" + str(items))
