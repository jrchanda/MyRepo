import sys
import inspect
import logging
logger = logging.getLogger(__name__)

__author__ = 'Balamurugan Ramu <balramu@cisco.com>'
__copyright__ = 'Copyright 2016, Cisco Systems'
__email__ = 'balramu@cisco.com'
__date__ = 'Sep 20,2016'
__version__ = 1.0


def dump_error_in_lib():
    curframe = inspect.currentframe()
    calframe = inspect.getouterframes(curframe, 2)
    logger.error("Error occured at the library function call name :" + str(calframe[1][3]))
    logger.error("Error occured is " + sys.exc_info().__str__())


def dump_error():
    curframe = inspect.currentframe()
    calframe = inspect.getouterframes(curframe, 2)
    logger.error("Error occured at the function call name :" + str(calframe[1][3]))
    logger.error("Error occured is " + sys.exc_info().__str__())


def get_host_mgmt_ip(config):
    ntw_list = config.host_info[0].nw_intf_list
    logger.info('Management interface is:' + ntw_list[0].is_mgmt_intf)
    for intf in ntw_list:
        if intf.is_mgmt_intf == 'yes':
            logger.info('Host Managment IP is: ' + intf.ip_address)
            host_ip = intf.ip_address
    return host_ip


def compare_lists(list1, list2):
    logger.info("list1: " + str(list1))
    logger.info("list2: " + str(list2))
    match = True
    if len(list1) == len(list2):
        for i in range(len(list2)):
            if list2[i] != list1[i]:
                match = False
                break
        if match is False:
            logger.error("Lists are not matched")
            return False
        else:
            logger.info("Both the list values are matched")
    else:
        logger.info("Length of two lists are not matching")
        return False


def compare_dictionaries(dict1, dict2):
    if dict1 == None or dict2 == None:
        return False

    if type(dict1) is not dict or type(dict2) is not dict:
        return False

    shared_keys = set(dict2.keys()) & set(dict2.keys())

    if not (len(shared_keys) == len(dict1.keys()) and len(shared_keys) == len(dict2.keys())):
        return False

    dicts_are_equal = True
    for key in dict1.keys():
        if type(dict1[key]) is dict:
            dicts_are_equal = dicts_are_equal and compare_dictionaries(dict1[key], dict2[key])
        else:
            dicts_are_equal = dicts_are_equal and (dict1[key] == dict2[key])
    return dicts_are_equal
