#!/usr/bin/python3
# Copyright: (c) 2018, Jeff Purcell <jeff.purcell@dell.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
author:  Dell EMC VxRail Ansible Team (@jpurcell3) <jeff.purcell@dell.com>
module: vcmode
short_description: This module is used to get the value of the VxRail vCenter Instance; Convert that instance to VxRail unmanged

description: The module reliease o=upon the VxRail network API to return details of the ESXi Nodes. The script includes filters to limit the properties returned by the module.
 - VxRail Manager has been deployed and is in good health
 - DNS settings have been applied for the new node host name and IP IPv4Address
 - Network configuration has been performed to support the additional network space required for the nodes.

options:

    name:
        description:
           - Name of the module. User defined name
        type: str
        required: false
    vcadmin:
        description:
            - The vcenter administrative user account defined to VxRail Manager
        type: str
        required: true
    vcpasswd:
        description:
            - The vcenter administrator password defined to VxRail Manager
        type: str
        required: true
    ip:
        description:
            - The VxRail Manager IP address. Note FQDN is not acceptable.
        type: str
        required: true
    mode:
        description:
            - vCenter mode setting. Supported options are list or 'EXTERNAL'
        type: str
        required: true
    timeout:
        description:
            - The timeout value, in milliseconds, assigned to the REST URL request. Default value is 10.
        type: int
        required: false

vserion_added: "2.9"

'''
EXAMPLES = """
- name: List VxRail vCenter Mode
  vcmode:
    vcadmin: "{{ vcadmin }}"
    vcpasswd: "{{ vcpasswd}}"
    ip: "{{ vxm_ip }}"
    mode: "{{ "list" }}"
  register: output

- debug:
     msg: "{{ output }}"



- name: Convert Embedded vCenter
  vcmode:
    vcadmin: "{{ vcadmin }}"
    vcpasswd: "{{ vcpasswd}}"
    ip: "{{ vxm_ip }}"
    mode: "{{ "external" }}"
  register: output

- debug:
    msg: "{{ output }}"

"""

RETURN = """
"""


# add package path if script run on VxRail manager
import time
import json
import logging
import requests
import chardet
import urllib3
from requests.exceptions import HTTPError
from ansible.module_utils.basic import AnsibleModule
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CustomLogFormatter(logging.Formatter):
    ''' Class for generating log output of this module'''
    info_fmt = "%(asctime)s [%(levelname)s]\t%(message)s"
    debug_fmt = "%(asctime)s [%(levelname)s]\t%(pathname)s:%(lineno)d\t%(message)s"

    def __init__(self, fmt="%(asctime)s [%(levelname)s]\t%(pathname)s:%(lineno)d\t%(message)s"):
        logging.Formatter.__init__(self, fmt)

    def format(self, record):
        if record.levelno == logging.INFO:
            self._fmt = CustomLogFormatter.info_fmt
            # python 3 compatibility
            if hasattr(self, '_style'):
                self._style._fmt = CustomLogFormatter.info_fmt
        else:
            self._fmt = CustomLogFormatter.debug_fmt
            # python 3 compatibility
            if hasattr(self, '_style'):
                self._style._fmt = CustomLogFormatter.debug_fmt
        result = logging.Formatter.format(self, record)
        return result

def byte_to_json(body):
    ''' method to convert http content to json  '''
    return json.loads(body.decode(chardet.detect(body)["encoding"]))


# Configurations
LOG_FILE_NAME = "/tmp/vx-vcmode.log"
LOG_FORMAT = CustomLogFormatter()


# Disable package info
logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.DEBUG)

# console ouput
CONSOLEHANDLER = logging.StreamHandler()
CONSOLEHANDLER.setLevel(logging.INFO)
CONSOLEHANDLER.setFormatter(LOG_FORMAT)
LOGGER.addHandler(CONSOLEHANDLER)

# file output
FILEHANDLER = logging.FileHandler(LOG_FILE_NAME)
FILEHANDLER.setLevel(logging.DEBUG)
FILEHANDLER.setFormatter(LOG_FORMAT)
LOGGER.addHandler(FILEHANDLER)

class ExpansionUrls():
    ''' Class performs mapping of VxRail APIs and class methods called within the module '''
    vc_mode_tpl = 'https://{}/rest/vxm/v1/vc/mode'
    vx_health_tpl = 'https://{}/rest/vxm/v1/cluster'
    conversion_progress_tpl = 'https://{}/rest/vxm/v1/requests/{}'


    def __init__(self, vxm_ip):
        '''init method'''
        self.vxm_ip = vxm_ip

    def getvc_mode(self):
        '''return the current vcenter configuration settings'''
        return ExpansionUrls.vc_mode_tpl.format(self.vxm_ip)

    def setvc_mode(self):
        return ExpansionUrls.vc_mode_tpl.format(self.vxm_ip)

    def vx_precheck(self):
        '''Map to VxRail node pre-check api'''
        return ExpansionUrls.vx_health_tpl.format(self.vxm_ip)

    def get_conversion_progress(self, taskid):
        '''return the current vcenter configuration settings'''
        return ExpansionUrls.conversion_progress_tpl.format(self.vxm_ip, taskid)


class vxrail():
    ''' Root Class for all mathods '''
    def __init__(self):
        self.vxm_ip = module.params.get('ip')
        self.timeout = module.params.get('timeout')
        self.vcadmin = module.params.get('vcadmin')
        self.vcpasswd = module.params.get('vcpasswd')
        self.auth = (self.vcadmin, self.vcpasswd)
        self.vcmode = (module.params.get('mode')).upper()
        self.expansion_urls = ExpansionUrls(self.vxm_ip)


    def precheck(self):
        ''' check for candidate nodes '''
        LOGGER.info("Performing pre-check of environment...")
        vx = {}
        try:
            response = requests.get(url=self.expansion_urls.vx_precheck(),
                                    verify=False,
                                    auth=self.auth,
                                    )
            response.raise_for_status()
        except HTTPError as http_err:
            LOGGER.error("HTTP error %s request to VxRail Manager %s", http_err, self.vxm_ip)
            return 'error'
        except Exception as api_exception:
            LOGGER.error(' %s Cannot connect to VxRail Manager %s', api_exception, self.vxm_ip)
            return 'error'

        if response.status_code == 200:
            data = byte_to_json(response.content)
            vx['state'] = data['health']
        LOGGER.info("Current vCenter Settings")
        LOGGER.info('   VxRail Health: %s', vx['state'])
        return vx


    def get_vc_mode(self):

        try:
            response = requests.get(url=self.expansion_urls.getvc_mode(),
                                    verify=False,
                                    auth=self.auth,
                                    )
            response.raise_for_status()
        except HTTPError as http_err:
            LOGGER.error("HTTP error %s request to VxRail Manager %s", http_err, self.vxm_ip)
            return 'error'
        except Exception as api_exception:
            LOGGER.error(' %s Cannot connect to VxRail Manager %s', api_exception, self.vxm_ip)
            return 'error'

        if response.status_code == 200:
            data = byte_to_json(response.content)
            return data['vc_mode']


    def create_vc_json(self):
        ''' validate list of nodes as '''
        LOGGER.info("Generatine JSON file...")
        convert_json = {}
        vc_admin = {}
        convert_json["psc_mode"] = "EXTERNAL"
        vc_admin["password"] = self.vcpasswd
        vc_admin["username"] = self.vcadmin
        convert_json["vc_admin_user"] = vc_admin
        convert_json["vc_mode"] = self.vcmode
        LOGGER.info(' JSON object:  %s', convert_json)
        return convert_json

    def convert_vc(self):
        ''' orchestrate the vcenter convertion task '''
        LOGGER.info("Converting embedded vCenter Server...")
        convert_json = vxrail().create_vc_json()
        headers = {'accept': 'application/json', 'Content-type': 'application/json'}

        try:
            response = requests.patch(url=self.expansion_urls.setvc_mode(),
                                      verify=False,
                                      headers=headers,
                                      auth=self.auth,
                                      data=json.dumps(convert_json),
                                      )
            response.raise_for_status()
        except HTTPError as http_err:
            LOGGER.error("HTTP error %s request to VxRail Manager %s", http_err, self.vxm_ip)
            return 'error'
        except Exception as api_exception:
            LOGGER.error(' %s Cannot connect to VxRail Manager %s', api_exception, self.vxm_ip)
            return 'error'

        if response.status_code == 401:
            vx = {}
            LOGGER.error('System returned an error. If Status Code is 405, system has already been converted: %s.', response)
            vx['state'] = "unchecked"
            vx['vc_mode'] = "unchecked"
            return vx
        if response.status_code == 202:
            LOGGER.info("Request returned sucessfull status")
            LOGGER.info(response)
            data = byte_to_json(response.content)
            LOGGER.info(data)
            request_id = data['request_id']
            LOGGER.info('Request Id: %s .', request_id)
            return request_id


    def track_conversion_status(self, task_id):
        ''' track the job status '''
        session = requests.Session()
        conversion_status = []
        try:
            response = session.get(url=self.expansion_urls.get_conversion_progress(task_id),
                                   verify=False,
                                   auth=self.auth
                                   )
        except Exception as http_err:
            LOGGER.error(http_err)
            LOGGER.error('Cannot connect to VxRail Manager %s.', self.vxm_ip)
            return 'error'

#        LOGGER.info(response.status_code)
        response_json = byte_to_json(response.content)
        conversion_status = response_json.get('state')
        LOGGER.info('Conversion Status: %s', conversion_status)
        if conversion_status == 'COMPLETED':
            LOGGER.info("The vCenter Conversion has completed")
        elif conversion_status == 'FAILED':
            LOGGER.info('Expansion Task %s has failed.', task_id)
            LOGGER.info(response_json['extension']['thoroughValidationFieldErrors'])
            LOGGER.info(response_json['extension']['normalValidationFieldErrors'])
        else:
            LOGGER.info('Inner track_conversion method: %s', conversion_status)
            time.sleep(30)

        return conversion_status


def main():
    ''' Go! '''
    global module
    module = AnsibleModule(
        argument_spec=dict(name=dict(required=False),
                           vcadmin=dict(default="administrator@vsphere.local"),
                           vcpasswd=dict(required=True, no_log=True),
                           ip=dict(required=True),
                           mode=dict(required=False),
                           timeout=dict(type='int', default=10),
                           ),
        supports_check_mode=True,
    )

    conversion_status = ''

    if module.params.get('mode').lower() == "list":
        vcmode = vxrail().get_vc_mode()
        if vcmode == 'error':
            module.fail_json(msg="Module cannot connect to VxRail Manager")
        vx_facts = {'mode' : vcmode}
        vx_facts_result = dict(changed=False, ansible_facts=vx_facts)
        module.exit_json(**vx_facts_result)


    if module.params.get('mode').upper() != "EXTERNAL":
        vx_facts = {'msg' : "invalid input"}
        vx_facts_result = dict(changed=False, ansible_facts=vx_facts)
        module.exit_json(**vx_facts_result)

    vcmode = vxrail().get_vc_mode()
    if vcmode.upper() != "EMBEDDED":
        vx_facts = {"VxRail Manager": module.params.get('ip'), "msg" : 'vCenter has already been externalized'}
        vx_facts_result = dict(changed=False, ansible_facts=vx_facts)
        module.exit_json(**vx_facts_result)

    health = vxrail().precheck()
    LOGGER.info(health)
    if health['state'] != "Healthy":
        vx_facts = {'msg' : "VxRail Cluster is not in 'Healthy' State. Please correct and retry"}
        vx_facts_result = dict(changed=False, ansible_facts=vx_facts)
        module.exit_json(**vx_facts_result)

    taskid = vxrail().convert_vc()
    LOGGER.info('Conversion Task: vxrail task_ID: %s.', taskid)
    while conversion_status not in ('COMPLETED', 'FAILED'):
        LOGGER.info("vcenter_conversion: sleeping 30 seconds...")
        time.sleep(30)
        conversion_status = vxrail().track_conversion_status(taskid)
        LOGGER.info('vcenter conversion: track_conversion status: %s', conversion_status)
    vx_facts = {'Conversion Status' : conversion_status}
    vx_facts_result = dict(changed=True, ansible_facts=vx_facts)
    module.exit_json(**vx_facts_result)

if __name__ == '__main__':
    main()
