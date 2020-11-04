#!/usr/bin/python3
# Copyright: (c) 2018, Jeff Purcell <jeff.purcell@dell.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
author:  Dell EMC VxRail Ansible Team (@jpurcell3) <jeff.purcell@dell.com>
module: add_vxrailhost
short_description: This module is used to automate VxRail node expansion by RESTful API

description: The module performs a cluster expansion using available nodes within a VxRail Cluster. It assumes the following
 - VxRail Manager has been deployed and is in good health
 - VxRail has free nodes which have been initialized and are available for the expansion task
 - DNS settings have been applied for the new node host name and IP IPv4Address
 - Network configuration has been performed to support the additional network space required for the nodes.

module: add_vxrailhost

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
        required: True
    esxhost:
        description:
            - The FQDN hostname assigned to the expansion node. Must be resolvable through DNS.
        type: str
        required: True
    vxuser:
        description:
            - The vxrail administrative account defined to vCenter and assosicated with teh VMware HCIA Management entitlement.
        type: str
        required: True
    vxpasswd:
        description:
            - The password for the vxuser account
        trype: str
        required: True
    esx_mgtip:
        description:
            - The IP address to be assigned to the management interface of the expansion node
        type: str
        required: true
    esx_vsan_ip:
        description:
            - The IP address to be assigned to the vSAN interface of the expansion node
        type: str
        required: true
    esx_vmotion:
        description:
            - The IP address to be assigned to the vMotion interface of the expansion node
        type: str
        required: true
    root_password:
        description:
            - The root password assigned to the node. Shoudl match the existing root password for other nodes in the cluster.
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
    - name: Add Node to existing VxRail Cluster
      vx-init:
        ip: "{{ vxm_ip }}"
        fname: "{{config_file}}"
        root_passwd: "{{ root_passwd }}"
    register: output

   - debug:
     msg: "{{ output }}"
"""

RETURN = """
"""



# add package path if script run on VxRail manager
import time
import json
import os
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
LOG_FILE_NAME = "node_expansion.log"
TMP_RETRY_FILE = "tmp_retry_id" # TBD
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
    validate_json_url_tpl = 'https://{}/rest/vxm/v1/system/initialize/validate?dryrun=true'
    status_url_tpl = 'https://{}/rest/vxm/v1/system/initialize/status'
    initialize_url_tpl = 'https://{}/rest/vxm/v1/system/initialize'

    def __init__(self, vxm_ip):
        '''init method'''
        self.vxm_ip = vxm_ip

    def post_url_validate_json(self):
        return ExpansionUrls.validate_json_url_tpl.format(self.vxm_ip)

    def post_url_initialize_cluster(self):
        return ExpansionUrls.initialize_url_tpl.format(self.vxm_ip)

    def get_url_task_status(self, job_id):
        return ExpansionUrls.status_url_tpl.format(self.vxm_ip, job_id)


class vxrail():
    ''' Root Class for all mathods '''
    def __init__(self):
        self.vxm_ip = module.params.get('ip')
        self.timeout = module.params.get('timeout')
        self.expansion_urls = ExpansionUrls(self.vxm_ip)


    def validate_json(self, config_json):
        payload = config_json
        content = {'Content-type': 'application/json'}
        try:
            response = requests.post(url=self.expansion_urls.post_url_validate_json(),
                                     headers=content,
                                     verify=False,
                                     auth=None,
                                     data=payload
                                     )
            response.raise_for_status()
            return response.content
        except HTTPError as http_err:
            LOGGER.error('HTTP error %s request to VxRail Manager.', http_err)
        except Exception as e:
            LOGGER.error('Error: %s. Cannot connect to VxRail Manager %s.', e, self.vxm_ip)

    def init_cluster(self, config_json):
        ''' Initiate Cluster deployment '''
        payload = config_json
        content = {'Content-type': 'application/json'}
        try:
            response = requests.post(
                url=self.expansion_urls.post_url_initialize_cluster(),
                headers=content,
                verify=False,
                auth=None,
                data=payload
                )
            response.raise_for_status()
            return response.content
        except HTTPError as http_err:
            LOGGER.error('HTTP error %s request to VxRail Manager %s.', http_err, self.vxm_ip)
        except Exception as e:
            LOGGER.error('Module ecountered an execption %s. Cannot connect to VxRail Manager %s.', e, self.vxm_ip)

    def get_task_status(self, job_id):
        ''' get task status '''
        response_json = []
        session = requests.Session()
        try:
            response = session.get(url=self.expansion_urls.get_url_task_status(job_id),
                                   verify=False,
                                   auth=None,
                                   )
        except Exception as http_err:
            LOGGER.error(http_err)
            LOGGER.error('Cannot connect to VxRail Manager %s.', self.vxm_ip)


        if response:
            response_json = byte_to_json(response.content)
            validation_status = response_json.get('state')
            LOGGER.info('Current Status: %s', validation_status)
            if validation_status == 'COMPLETED':
                LOGGER.info("Node validation has completed")
            elif validation_status == 'FAILED':
                LOGGER.info('Validation Task %s has failed.', job_id)
                LOGGER.info(response_json['extension']['normalValidationFieldErrors'])
                LOGGER.info(response_json['extension']['thoroughValidationFieldErrors'])
            else:
                time.sleep(10)
        return validation_status

def main():
    ''' Go! '''
    global module
    module = AnsibleModule(
        argument_spec=dict(name=dict(required=False),
                           ip=dict(required=True),
                           fname=dict(required=True),
                           timeout=dict(type='int', default=10),
                           ),
        supports_check_mode=True,
    )


    validation_status, init_status = ''
    if os.path.isfile(module.params.get('fname')):
        LOGGER.info('VxRail Iniitalizaion using JSON file %s', module.params.get('fname'))
        config_json = json.load(module.params.get('fname'))
    else:
        LOGGER.error('File cannot not be opened or does not exit, please verify and try again')
        module.fail_json(msg="JSON file not found!")

    LOGGER.info("Validating the JSON input file...")
    jobid = vxrail().validate_json(config_json)
    LOGGER.info('validate json conifg: VxRail task id: %s.', jobid)
    while validation_status not in ('COMPLETED', 'FAILED'):
        validation_status = vxrail().get_task_status(jobid)
        LOGGER.info("expansion_validation: Sleeping 60 seconds before checking for status...")
        time.sleep(60)
    if validation_status == 'COMPLETED':
        LOGGER.info("Validation completed") 

    vx_facts = {'initialization_status' : init_status}
    vx_facts_result = dict(changed=False, ansible_facts=vx_facts)
    module.exit_json(**vx_facts_result)

if __name__ == '__main__':
    main()
