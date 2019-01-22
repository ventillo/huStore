#!/usr/bin/python -u

'''
--------------------------------------------------------------------------------
    Type:           Python 2.x script
    Author:         Milan Toman (milan.v.toman@gmail.com)
    Description:    Huawei Oceanstor API library and CLI

    TOOD:

--------------------------------------------------------------------------------
            Import libraries
--------------------------------------------------------------------------------
'''
# mandatory
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import urllib
import json
import sys
import os
import re
import textwrap
import getpass
# getopt or argparse, not sure which to go by
import argparse
#import getopts
import time
import datetime
import logging
# optional
from pprint import pprint

'''
--------------------------------------------------------------------------------
            Define variables
--------------------------------------------------------------------------------
'''
global out
global principal
global _VERSION, _NAME
global _GB, _KB, _MB, _TB
_KB = 2
_MB = _KB * 1024
_GB = _MB * 1024
_TB = _GB * 1024
_PRECISION = 10
_VERSION = 0.9
_NAME = u"Huawei rest client"
_LOG_DIR_POSTFIX = u'/log/'
_LOG_FILE_ROOT = sys.path[0]
_CURRENT_DIR = sys.path[0]
_FILE_NAME = sys.argv[0].split('/')[-1]
_LOG_FILE = _LOG_FILE_ROOT + _LOG_DIR_POSTFIX + _FILE_NAME + u'.log'
_LOG_DIR = _LOG_FILE_ROOT + _LOG_DIR_POSTFIX
_DEBUG_FILE = _LOG_FILE_ROOT + _LOG_DIR_POSTFIX + _FILE_NAME +u'.dbg'

#disable certificate warnings
requests.packages.urllib3.disable_warnings()
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Huawei specific
_HOST = ''
global _PORT
_PORT = 8088
_USER = u''
_PASS = u''
_ADMIN = False

systems = {'6800': [u'host1', u'host2', u'host3', u'host4'],
           '5500': [u'host2', u'host3', u'host1']}
# scope -> user scope: 0 - local user, 1 - LDAP / AD user
#_SCOPE = 1


'''
--------------------------------------------------------------------------------
            Set up logging
--------------------------------------------------------------------------------
'''
# Check log directory and create if non-existent
if os.path.isdir(_LOG_DIR):
    # print "INFO: Log directory \"{}\" exists.".format(_LOG_DIR)
    files = os.listdir(_LOG_DIR)
    logfile_dict = {}
    for file in files:
        if _LOG_FILE_ROOT in file:
            file_path = os.path.join(_LOG_DIR, file)
            file_stats = os.stat(file_path)
            file_mtime = file_stats.st_mtime
            #if datetime.datetime.now() - file_stats.st_mtime > datetime.timedelta(hours=24)
            try:
                logfile_dict.update({file_path: file_mtime})
            except:
                logfile_dict = {file_path: file_mtime}
        else:
            pass
    sorted_list_keys = sorted(logfile_dict, key=logfile_dict.get)
    # select the last 30 log files to keep, delete the rest.
    files_to_keep = sorted_list_keys[-30:]
    for filename in sorted_list_keys:
        if filename not in files_to_keep:
            #print("Deleting {}".format(filename))
            os.remove(filename)
        else:
            #print("Not deleting {}".format(filename))
            pass
else:
    try:
        os.mkdir(_LOG_DIR)
        # print "INFO: Created logging directory \"{}\"".format(_LOG_DIR)
    except () as error:
        print(u"FATAL: Unable to create " +\
              u"logging directory \"{}\"".format(_LOG_DIR))
        raise SystemError(u"Unable to create log directory %s", error)

# Check for previous logs and rename if any
if os.path.isfile(_LOG_FILE):
    timestapmp_logfile = os.path.getmtime(_LOG_FILE)
    date_logfile = datetime.datetime.fromtimestamp(timestapmp_logfile)
    _LOG_RENAME = _LOG_FILE + "." + date_logfile.strftime("%Y%m%d%H%M%S")
    os.rename(_LOG_FILE, _LOG_RENAME)
if os.path.isfile(_DEBUG_FILE):
    timestapmp_logfile = os.path.getmtime(_DEBUG_FILE)
    date_logfile = datetime.datetime.fromtimestamp(timestapmp_logfile)
    _DEBUG_RENAME = _DEBUG_FILE + "." + date_logfile.strftime("%Y%m%d%H%M%S")
    os.rename(_DEBUG_FILE, _DEBUG_RENAME)

# Cleanup if more than _MAX_LOGS / _MAX_LOGS_SIZE logs are present
    # TODO

# Setup formatting
_basic_format = "%(asctime)s %(name)s %(levelname)s %(message)s"
_basic_formatter = logging.Formatter(_basic_format)
_debug_format = "%(asctime)s %(name)s[%(process)d] \
                 (%(funcName)s) %(levelname)s %(message)s"
_debug_formatter = logging.Formatter(_debug_format)
_console_format = "%(name)s %(levelname)s: %(message)s"
_console_formatter = logging.Formatter(_console_format)

# Make logging readable with module hierarchy
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Setting up handlers for stdout / file logging and debug
# Logfile
basic_handler = logging.FileHandler(_LOG_FILE)
basic_handler.setLevel(logging.ERROR)
basic_handler.setFormatter(_basic_formatter)
logger.addHandler(basic_handler)

# Debug file
debug_handler = logging.FileHandler(_DEBUG_FILE)
debug_handler.setLevel(logging.DEBUG)
debug_handler.setFormatter(_debug_formatter)
logger.addHandler(debug_handler)

# Console
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.CRITICAL)
console_handler.setFormatter(_console_formatter)
logger.addHandler(console_handler)

# Just for debugging
# print _LOG_FILE, _DEBUG_FILE
# logger.debug(u'debug message')
# logger.info(u'info message')
# logger.warn(u'warn message')
# logger.error(u'error message')
# logger.critical(u'critical message')


'''
--------------------------------------------------------------------------------
            Setup arguments and Options
--------------------------------------------------------------------------------
'''
desc = u'''\
DESCRIPTION:
    Huawei OceanStor REST API troubleshooting and monitoring script
    '''
epi = u'''\
    ERROR CODES:
         1:

    EXAMPLES:

    '''
formatter = argparse.RawDescriptionHelpFormatter
arg_parser = argparse.ArgumentParser(description = desc,
                                     formatter_class = formatter,
                                     epilog = textwrap.dedent(epi))
ip_help = u'IP or FQDN of the Huawei storage box'
user_help = u'Username, obviously'
password_help = u'Optionally, the password may be supplied'
admin_help = u'Optionally, the password may be supplied'
info_help = u'Information section. You can optionally select one ' +\
            u'or more categories'
failed_help = u'Optionally, you might filter only failed components'

arg_parser.add_argument('-i', '--host',
                        type = str,
                        help = ip_help,
                        nargs = '+')
arg_parser.add_argument('-u', '--user',
                        type = str,
                        help = user_help)
arg_parser.add_argument('-p', '--password',
                        type = str,
                        help = password_help)
arg_parser.add_argument('-A', '--admin',
                        action = 'store_true',
                        help = admin_help)
arg_parser.add_argument('-d', '--details',
                        type = str,
                        help = info_help,
                        nargs='*',
                        choices = ['system','pool','disk','host', 'perf'])
arg_parser.add_argument('-f', '--failed',
                        action = 'store_true',
                        help = failed_help)

args = arg_parser.parse_args()
_HOST = args.host
_USER = args.user
_PASS = args.password
_DETAILS = args.details
_FAILED = args.failed
_ADMIN = args.admin

'''
--------------------------------------------------------------------------------
            Generic, standalone functions
--------------------------------------------------------------------------------
'''
def printline():
    line = ''
    for i in range(0, 79):
        line = line + '-'
    return line

def print_stuff(content, **kwargs):
    if 'iter' in kwargs.keys():
        iteration = kwargs['iter']
    else:
        iteration = 0
    pause = u''
    for i in range(0, iteration):
        try:
            pause = pause + '  '
        except:
            pause = '  '
    if type(content) is type(dict()):
        for element in content.keys():
            print "{}[ {} ]".format(pause, element)
            print_stuff(content[element], iter = iteration + 1)
    elif type(content) is type(list()):
        for element in content:
            print_stuff(element, iter = iteration + 1)
    elif type(content) is type(str()) or type(int()):
            print "{} -> \"{}\"".format(pause, content)




'''
--------------------------------------------------------------------------------
            Classes
--------------------------------------------------------------------------------
'''
class huaweiResultFormater(object):
    """Format the sections and results which we get from the get functions.
    These are all proprietary functions, expecting huawei dicts as input. """
    def __init__(self):
        self.__name__ = u'Result Formatter'

    def formatSysInfo(self, section_name):
        print(u'\n' + section_name + u'\n' + printline())
        system_information = oceanstor.huGet('/system/')
        for system_info in system_information['data'].keys():
            print("{:30}: {:30}".format(
                    system_info,
                    system_information['data'][system_info])
                 )


    def formatHosts(self, host_dict, section_name):
        print(u'\n' + section_name + u'\n' + printline())
        print("{:6} {:13} {:10} {:10} {:15}".format('ID',
                                                'NAME',
                                                'HEALTHY',
                                                'RUNNING',
                                                'HOST_TYPE'))
        print printline()
        host_types = {'0': 'Linux',
                    '1': 'Windows',
                    '2': 'Solaris',
                    '3': 'HP-UX',
                    '4': 'AIX',
                    '5': 'XenServer',
                    '6': 'Mac OS',
                    '7': 'VMware ESX',
                    '8': 'LINUX_VIS',
                    '9': 'Windows Server 2012',
                    '10': 'Oracle VM',
                    '11': 'OpenVMS'}
        healthy_types = {'1': 'yes', '0': 'no'}
        running_types = {'1': 'yes', '0': 'no'}
        for n in range(0, 255): #int(hosts['data']['COUNT'])):
            try:
                host = oceanstor.huGet('/host/' + str(n))
                #pprint.pprint(host)
                id = host['data']['ID']
                name = host['data']['NAME']
                host_type = host_types[host['data']['OPERATIONSYSTEM']]
                in_host_group = host['data']['ISADD2HOSTGROUP']
                running = running_types[host['data']['RUNNINGSTATUS']]
                healthy = healthy_types[host['data']['HEALTHSTATUS']]
                parent_type = host['data']['PARENTTYPE']
                print("{:6} {:13} {:10} {:10} {:2}".format(id,
                                                    name,
                                                    healthy,
                                                    running,
                                                    host_type))
            except:
                pass
                #print("{:6} {:13} {:10} {:10} {:2}".format('-',
                #                                    '-',
                #                                    '-',
                #                                    '-',
                #                                    '-'))

    def formatPoolInfo(self, section_name):
        print(u'\n' + section_name + u'\n' + printline())
        print("{:<3} {:>15} ".format('ID', "TOTAL [TB]") +\
              "{:>15} {:>15} {:>10}".format("FREE [GB]","USED [GB]", "USED [%]"))
        print printline()
        pool_count = oceanstor.huGet('/storagepool/count')
        for n in range(0, int(pool_count['data']['COUNT'])):
            pool = oceanstor.huGet('/storagepool/' + str(n))
            id = n
            #pprint(pool)
            #DATASPACE = round(float(pool['data']['DATASPACE']), _PRECISION)
            USERTOTALCAPACITY = round(float(
                pool['data']['USERTOTALCAPACITY']) / _GB, _PRECISION)
            USERFREECAPACITY = round(float(
                pool['data']['USERFREECAPACITY']) / _GB, _PRECISION)
            USERCONSUMEDCAPACITY = round(float(
                pool['data']['USERCONSUMEDCAPACITY']) / _GB, _PRECISION)
            print "{:<3} {:>15.2f}".format(id,
                    USERTOTALCAPACITY)\
                + "{:>16.2f} {:15.2f} {:10.2f}".format(
                    USERFREECAPACITY,
                    USERCONSUMEDCAPACITY,
                    USERCONSUMEDCAPACITY / USERTOTALCAPACITY * 100)

    def formatDiskInfo(self, section_name):
        print(u'\n' + section_name + u'\n' + printline())
        log_type_def = {
            '1': 'free',
            '2': 'member',
            '3': 'spare',
            '4': 'cache'
            }
        health_def = {
            '0': 'unknown',
            '1': 'normal',
            '2': 'faulty',
            '3': 'failing'
        }
        running_types = {
            '0': 'unknown',
            '1': 'normal',
            '14': 'pre-copy',
            '16': 'reconstruction',
            '27': 'online',
            '28': 'offline',
        }
        type_types = {
            '0': 'FC',
            '1': 'SAS',
            '2': 'SATA',
            '3': 'SSD',
            '4': 'NL-SAS',
            '5': 'SLC SSD',
            '6': 'MLC SSD'
        }

        disk_info = oceanstor.huGet('/disk')
        print("{:4} {:5} {:12} {:10} {:8} {:8} {:8} {:3}".format(
                                                'id','tech', 'location',
                                                'type', 'status',
                                                'progress', 'uptime',
                                                'temp'
                                                )
                 )
        print printline()
        """
        {u'ABRASIONRATE': u'0',
            u'BANDWIDTH': u'6000',
            u'CAPACITYUSAGE': u'68',
            u'DISKFORM': u'2',
            u'DISKIFTYPE': u'0',
            u'DISKPORTADDR': u'59C37F486234D013',
            u'DISKTYPE': u'1',
            u'ELABEL': u'[Board Properties]\nBoardType=STLZA1SAS600\nBarCode=210235966010F4000300\nItem=02359660\nDescription=OceanStor 5600/5800/6800/6900 V3,STLZA1SAS600,600GB 15K RPM SAS Disk Unit&#40;3.5"&#41;,sectorsize-520\nManufactured=2015-04-27\nVendorName=Huawei\nIssueNumber=00\nCLEICode=\nBOM=\n',
            u'FIRMWAREVER': u'0008',
            u'HEALTHMARK': u'82',
            u'HEALTHSTATUS': u'1',
            u'ID': u'339',
            u'ISCOFFERDISK': u'false',
            u'ITEM': u'02359660',
            u'LIGHTSTATUS': u'0',
            u'LOCATION': u'DAE082.19',
            u'LOGICTYPE': u'2',
            u'MANUFACTURER': u'Seagate',
            u'MODEL': u'ST3600057SS',
            u'MULTIPATH': u'["C","D"]',
            u'PARENTID': u'10',
            u'PARENTTYPE': 206,
            u'POOLID': u'1',
            u'POOLNAME': u'DD_ENG1',
            u'POOLTIERID': u'1.1',
            u'PROGRESS': u'0',
            u'REMAINLIFE': u'0',
            u'RUNNINGSTATUS': u'27',
            u'RUNTIME': u'768',
            u'SECTORS': u'1146125998',
            u'SECTORSIZE': u'520',
            u'SERIALNUMBER': u'6SL9Z1RH0000N531AM2Q',
            u'SMARTCACHEPOOLID': u'4294967295',
            u'SPEEDRPM': u'15000',
            u'STORAGEENGINEID': u'1',
            u'TEMPERATURE': u'35',
            u'TYPE': 10,
            u'barcode': u'210235966010F4000300',
            u'formatProgress': u'0',
            u'formatRemainTime': u'0'}
        """
        for disk in disk_info['data']:
            location = disk['LOCATION']
            used = disk['CAPACITYUSAGE']
            dtype = type_types[disk['DISKTYPE']]
            health_mark = disk['HEALTHMARK']
            health = health_def[disk['HEALTHSTATUS']]
            id = disk['ID']
            coffer = disk['ISCOFFERDISK']
            log_type = log_type_def[disk['LOGICTYPE']]
            manuf = disk['MANUFACTURER']
            multipath = disk['MULTIPATH']
            poolid = disk['POOLID']
            poolname = disk['POOLNAME']
            pooltier = disk['POOLTIERID']
            status = running_types[disk['RUNNINGSTATUS']]
            progress = disk['PROGRESS']
            uptime = disk['RUNTIME']
            temp = disk['TEMPERATURE']
            if _FAILED:
                if 'offline' in status:
                    print("{:4} {:5} {:12} {:10} {:8} {:8} {:8} {:3}".format(
                                                id, dtype, location,
                                                log_type, status,
                                                progress, uptime,
                                                temp
                                                )
                    )
            else:
                print("{:4} {:5} {:12} {:10} {:8} {:8} {:8} {:3}".format(
                                                id, dtype, location,
                                                log_type, status,
                                                progress, uptime,
                                                temp
                                                )
                )


class huaweiOceanstor(object):
    """Huawei OceanStor REST API caller and connector """

    def __init__(self, ip, port):
        """Initialization of the Huawei object, some things need to be set by
        default

        Args:
            ip: str(), ip or FQDN of the Huawei box
            port: int(), port to communicate on via REST. e.g. 8088

        Returns:
            status: bool, result of init.

        Sets:
            self.__rest_path__: str(), base path for REST calls
            self.__iBaseToken__: str(), specific token for AAA of Huawei boxes
                                 if not authenticated, is set to None type
            self.__host_port__: int(), port for communication. Default 8088
            self.__complete_rest__: str(), complete paths, minus the target call
            self.__call_headers__: dict(), headers according to huawei manual
        """
        self.__rest_path__ = '/deviceManager/rest'
        self.__iBaseToken__ = None
        self.__sessionCookie__ = None
        self.__deviceId__ = '/xxxxx'
        self.__host_port__ = 'https://' + ip + ':' + str(port)
        self.__complete_rest__ = self.__host_port__ + self.__rest_path__
        self.__call_headers__ = {
            "Content-Type": "application/json; charset=utf-8"}


    def huResultCheck(self, response):
        """ Check to return a boolean value if the command went OK, or an error
        occured. Handles non-standard and out of bound responses as well

        Args:
            response: dict(), response dict, deserialized from Json that needs
                      checking

        Returns:
            bool, based on the outcome of result, that is sent back by Huawei

        Sets:
            self.__last_call_result__: bool
            self.__last_call_reason__: str(), reson / description of the error
                                       value
            self.__last_call_code__: int(): response code once again, in class
                                            name space
        """
        if type(response) is type(dict()):
            try:
                error_code = int(response['error']['code'])
                error_reason = response['error']['description']
            except () as check_err:
                logger.error("Response in unknown format: %s", response)
            if error_code == 0:
                self.__last_call_result__ = True
                self.__last_call_code__ = error_code
                self.__last_call_reason__ = error_reason
                return True
            else:
                self.__last_call_result__ = False
                self.__last_call_code__ = error_code
                self.__last_call_reason__ = error_reason
                return False
        else:
            logger.error("Response returned from Array not a dict: %s",
                         response)
            self.__last_call_result__ = False
            self.__last_call_code__ = -1
            self.__last_call_reason__ = None
            return False

    def huGet(self, call_target):
        """ An http POST call for Huawei REST API.

            Args:
                call_target: str(), last portion of URL, e.g. '/deviceid/user'
        """
        full_url = self.__complete_rest__ + self.__deviceId__ + call_target
        jar = requests.cookies.RequestsCookieJar()
        jar.set('session', self.__sessionCookie__)
        try:
            r = requests.get(full_url,
                             headers = self.__call_headers__,
                             verify = False,
                             cookies = jar)
        except () as error:
            print "Can't connect to API server URL: " +\
                  "{},\n reson: {} ".format(targetUrl, error)
            raise SystemError(error)
        try:
            responseObj = json.loads(r.text)
            self.__sessionCookie__ = r.cookies[u'session']
            return responseObj
        except:
            logger.error(u"Exception in converting data to JSON: %s", r.text)
            raise SystemError(u"Exception in converting data to JSON")


    def huPost(self, call_target, call_post_payload):
        """ An http POST call for Huawei REST API.

        Args:
            call_target: str(), last portion of URL, e.g. '/xxxxx/sessions'
            call_post_payload: dict(), dictionary to form the JSON call from

        Returns:
            responseObj: dict(), dict from Json returned by the array. Contains
                                 {u'data':
                                     {u'...': u'...', ...},
                                  u'error':
                                     {u'code': int(), u'decription': str()}
                                 }
        Sets:
            self.__sessionCookie__: str(), session cookie that needs to be
                                           present on each single subsequential
                                           call after authentication
        """
        full_url = self.__complete_rest__ + self.__deviceId__ + call_target
        postJson = json.dumps(call_post_payload, sort_keys=True, indent=4)
        jar = requests.cookies.RequestsCookieJar()
        jar.set('session', self.__sessionCookie__)
        try:
            r = requests.post(full_url,
                              postJson,
                              headers=self.__call_headers__,
                              verify = False,
                              cookies = jar)
        except () as error:
            print "Can't connect to API server URL: " +\
                  "{},\n reson: {} ".format(targetUrl, error)
            raise SystemError(error)
        try:
            responseObj = json.loads(r.text)
            self.__sessionCookie__ = r.cookies[u'session']
            return responseObj
        except:
            logger.error(u"Exception in converting data to JSON: %s", r.text)
            raise SystemError(u"Exception in converting data to JSON")


    def huPostURLlib(self, call_target, call_post_payload):
        """ An http POST call for Huawei REST API.

        Args:
            call_target: str(), last portion of URL, e.g. '/xxxxx/sessions'
            call_post_payload: dict(), dictionary to form the JSON call from

        Returns:
            responseObj: dict(), dict from Json returned by the array. Contains
                                 {u'data':
                                     {u'...': u'...', ...},
                                  u'error':
                                     {u'code': int(), u'decription': str()}
                                 }
        Sets:
            self.__sessionCookie__: str(), session cookie that needs to be
                                           present on each single subsequential
                                           call after authentication
        """

        full_url = self.__complete_rest__ + self.__deviceId__ + call_target
        postJson = json.dumps(call_post_payload, sort_keys=True, indent=4)
        jar = requests.cookies.RequestsCookieJar()
        jar.set('session', self.__sessionCookie__)
        try:
            result = urllib.urlopen(full_url, data=postJson, headers=self.__call_headers__)
            #r = requests.post(full_url, postJson, headers=self.__call_headers__, verify = False, cookies = jar)
        except () as error:
            print "Can't connect to API server URL: " +\
                  "{},\n reson: {} ".format(targetUrl, error)
            raise SystemError(error)
        try:
            responseObj = json.loads(r.text)
            self.__sessionCookie__ = r.cookies[u'session']
            return responseObj
        except:
            logger.error(u"Exception in converting data to JSON: %s", r.text)
            raise SystemError(u"Exception in converting data to JSON")


    def huPut(self, call_target, call_put_payload):
        """ An http PUT call for Huawei REST API.

        Args:
            call_target: str(), last portion of URL, e.g. '/xxxxx/sessions'
            call_put_payload: dict(), dictionary to form the JSON call from

        Returns:
            responseObj: dict(), dict from Json returned by the array. Contains
                                 {u'data':
                                     {u'...': u'...', ...},
                                  u'error':
                                     {u'code': int(), u'decription': str()}
                                 }
        Sets:
            self.__sessionCookie__: str(), session cookie that needs to be
                                           present on each single subsequential
                                           call after authentication
        """
        full_url = self.__complete_rest__ + self.__deviceId__ + call_target
        PutJson = json.dumps(call_put_payload, sort_keys=True, indent=4)
        jar = requests.cookies.RequestsCookieJar()
        jar.set('session', self.__sessionCookie__)
        print PutJson
        try:
            r = requests.put(full_url,
                             PutJson,
                             headers=self.__call_headers__,
                             verify = False,
                             cookies = jar)
        except () as error:
            print "Can't connect to API server URL: " +\
                  "{},\n reson: {} ".format(targetUrl, error)
            raise SystemError(error)
        try:
            responseObj = json.loads(r.text)
            self.__sessionCookie__ = r.cookies[u'session']
            return responseObj
        except:
            logger.error(u"Exception in converting data to JSON: %s", r.text)
            raise SystemError(u"Exception in converting data to JSON")

    def huDelete(self, call_target):
        """ An http DELETE call for Huawei REST API.

            Args:
                call_target: str(), last portion of URL, e.g. '/deviceid/user'
        """
        full_url = self.__complete_rest__ + self.__deviceId__ + call_target
        jar = requests.cookies.RequestsCookieJar()
        jar.set('session', self.__sessionCookie__)
        try:
            r = requests.delete(full_url,
                                headers = self.__call_headers__,
                                verify = False,
                                cookies = jar)
        except () as error:
            print "Can't connect to API server URL: " +\
                  "{},\n reson: {} ".format(targetUrl, error)
            raise SystemError(error)
        try:
            responseObj = json.loads(r.text)
            self.__sessionCookie__ = r.cookies[u'session']
            return responseObj
        except:
            logger.error(u"Exception in converting data to JSON: %s", r.text)
            raise SystemError(u"Exception in converting data to JSON")

    def huAuth(self, username, password, user_scope):
        """
        Args:
            username: str(), username, one time use
            password: str(), password, one time use
            user_scope: int(), 0 = local user, 1 = ldap user

        Returns:
            status: bool, true if authenticated, false if unauthorized, or
                    other exception

        Sets:
            self.__iBaseToken__: str()
            self.__sessionCookie__: str()
            self.__devideId__: str()
        """
        post_payload = {u"username": username,
                        u"password": password,
                        u"scope": user_scope}
        auth_link = '/sessions'
        call_result = self.huPost(auth_link, post_payload)
        if self.huResultCheck(call_result):
            self.__iBaseToken__ = call_result[u'data'][u'iBaseToken']
            self.__call_headers__.update({u'iBaseToken': self.__iBaseToken__})
            self.__deviceId__ = '/' + call_result[u'data'][u'deviceid']
            return True
        else:
            return False

    def huDeAuth(self):
        """ De-authenticate user, delete session cookies and session data on
        storage frame

        Args:

        Returns:
            status: bool, true if deauthenticated, false if session deletion did
                    not succeed

        Sets:
            self.__iBaseToken__: str(), sets to empty string
            self.__sessionCookie__: str(), sets to empty string
            self.__deviceId__: str()
        """
        delete_link = '/sessions'
        call_result = self.huDelete(delete_link)
        if self.huResultCheck(call_result):
            self.__iBaseToken__ = u''
            self.__call_headers__[u'iBaseToken'] = ''
            self.__deviceId__ = ''
            return True
        else:
            return False


# Main
if '__main__':
    if _USER is None and not _ADMIN:
        _USER = raw_input(u'Username:')
    if _PASS is None and not _ADMIN:
        _PASS = getpass.getpass(u'Password:')
    _SCOPE = 0
    #print(_DETAILS)
    for host in _HOST:
        if _ADMIN == True:
            print(u'Admin mode')
            _USER = u'admin'
            with open(_CURRENT_DIR + '/id.pass', 'r') as passfilehandler:
                pass_data = eval(passfilehandler.readlines()[0])
            if host in systems['6800']:
                _PASS = pass_data['6800']
                print("6800V3 detected")
            elif host in systems['5500']:
                _PASS = pass_data['5500']
                print("5500V3 detected")
        oceanstor = huaweiOceanstor(host, _PORT)
        result = oceanstor.huAuth(_USER, _PASS, _SCOPE)
        formatPrinter = huaweiResultFormater()
        #printline()
        """
        ------------------------------------------------------------------------
        Get system information
        ------------------------------------------------------------------------
        """
        if _DETAILS is None or 'system' in _DETAILS:
            formatPrinter.formatSysInfo('System information')
            print printline()
        if 'pool' in _DETAILS:
            """
            --------------------------------------------------------------------
            Get pool information
            --------------------------------------------------------------------
            """
            formatPrinter.formatPoolInfo('Pool Information')
            print printline()
        if 'disk' in _DETAILS:
            """
            --------------------------------------------------------------------
            Get disk information
            --------------------------------------------------------------------
            """
            formatPrinter.formatDiskInfo('Physical disk Information')
            print printline()
        if 'host' in _DETAILS:
            """
            --------------------------------------------------------------------
            Get a list of initiators
            --------------------------------------------------------------------
            """
            hosts = oceanstor.huGet('/host/count')
            formatPrinter.formatHosts(hosts, 'Host Information')
            print printline()
        if 'perf' in _DETAILS:
            """
            --------------------------------------------------------------------
            Get some performance data
            --------------------------------------------------------------------
            """
            ports = oceanstor.huGet('/fc_port')
            print(ports)
            perf_details = oceanstor.huGet('/performace_statistic/cur_statistic_data?CMO_STATISTIC_UUID=212:1649318888706&CMO_STATISTIC_DATA_ID_LIST=21,25')
            print(perf_details)
            print(printline())
        """
        ------------------------------------------------------------------------
        End / deauth / log-off
        ------------------------------------------------------------------------
        """

        # destroy session on Huawei
        deauth = oceanstor.huDeAuth()
        print("Deauthenticated from {}: {}".format(host, deauth))
    # end of script marker
    print printline()
