#!/bin/python -u

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
import pprint

'''
--------------------------------------------------------------------------------
            Define variables
--------------------------------------------------------------------------------
'''
global out
global principal
global _VERSION, _NAME
global _GB, _KB, _MB, _TB
_KB = 1024
_MB = _KB*1024
_GB = _MB*1024
_TB = _GB*1024
_PRECISION = 3
_VERSION = 0.9
_NAME = u"Huawei rest client"
_LOG_DIR = u'./log/'
_LOG_FILE = _LOG_DIR + re.sub(u'./', '', sys.argv[0]) + u'.log'
_DEBUG_FILE = _LOG_DIR + re.sub(u'./', '', sys.argv[0]) + u'.dbg'

#disable certificate warnings
requests.packages.urllib3.disable_warnings() 

# Huawei specific
_HOST = ''
_PORT = 8088
_USER = u''
_PASS = u''
# scope -> user scope: 0 - local user, 1 - LDAP / AD user
_SCOPE = 1


'''
--------------------------------------------------------------------------------
            Set up logging
--------------------------------------------------------------------------------
'''
# Check log directory and create if non-existent
if os.path.isdir(_LOG_DIR):
    # print "INFO: Log directory \"{}\" exists.".format(_LOG_DIR)
    pass
else:
    try:
        os.mkdir(_LOG_DIR)
        # print "INFO: Created logging directory \"{}\"".format(_LOG_DIR)
    except () as error:
        print u"FATAL: Unable to create " +\
              u"logging directory \"{}\"".format(_LOG_DIR)
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
    Huawei OceanStor REST API caller and connector suite
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
arg_parser.add_argument('-i', '--ip',
                        type = str, 
                        help = ip_help)
arg_parser.add_argument('-u', '--user',
                        type = str, 
                        help = user_help)
arg_parser.add_argument('-p', '--password',
                        type = str,
                        help = password_help)
args = arg_parser.parse_args()
_HOST = args.ip
                   

'''
--------------------------------------------------------------------------------
            Generic, standalone functions
--------------------------------------------------------------------------------
'''         
def printline():
    line = ''
    for i in range(0, 79):
        line = line + '-'
    print line
    
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
        
        
        
    def huPut():
        pass
        
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
    _USER = raw_input(u'Username:')
    _PASS = getpass.getpass(u'Password:')
    oceanstor = huaweiOceanstor(_HOST, _PORT)
    oceanstor.huAuth(_USER, _PASS, _SCOPE)
    printline()
    pool_count = oceanstor.huGet('/storagepool/count')
    for n in range(0, int(pool_count['data']['COUNT'])):
        pool = oceanstor.huGet('/storagepool/' + str(n))
        id = n
        DATASPACE = round(float(pool['data']['DATASPACE'])/_GB, _PRECISION)
        USERTOTALCAPACITY = round(float(
            pool['data']['USERTOTALCAPACITY'])/_GB, _PRECISION)
        USERFREECAPACITY = round(float(
            pool['data']['USERFREECAPACITY'])/_GB, _PRECISION)
        USERCONSUMEDCAPACITY = round(float(
            pool['data']['USERCONSUMEDCAPACITY'])/_GB, _PRECISION)
        print "id:{} {} -> TOTAL:{} ".format(id, DATASPACE, USERTOTALCAPACITY)\
              + "FREE:{} USED:{}".format(USERFREECAPACITY, USERCONSUMEDCAPACITY)
    '''
    hosts = oceanstor.huGet('/host/count')
    print hosts['data']
    for n in range(0, int(hosts['data']['COUNT'])):
        host = oceanstor.huGet('/host/' + str(n))
        id = host['data']['ID']
        name = host['data']['NAME']
        initiator = host['data']['INITIATORNUM']
        print "{}: {} -> {}".format(id, name, initiator)
    '''

    """
    ----------------------------------------------------------------------------
    End / deauth / log-off
    ----------------------------------------------------------------------------
    """
    # end of script marker
    printline()
    # destroy session on Huawei
    deauth = oceanstor.huDeAuth()
