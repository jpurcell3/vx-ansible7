#!/usr/bin/python3
# Copyright: (c) 2018, Jeff Purcell <jeff.purcell@dell.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
author:  Dell EMC VxRail Ansible Team (@jpurcell3) <jeff.purcell@dell.com>
module: vx_lcm
short_description: This module is used to upgrade a VxRail Cluster

description: The module will perorm a VxRail Cluster using a VxRail Composite Bundle, and provide real time upgrade status through the log file. 
 - VxRail Manager has been deployed and is in good health
 - DNS settings have been applied for the new node host name and IP IPv4Address
 - Network configuration has been performed to support the additional network space required for the nodes.
 - VxRail Bundle for the target release

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
    bundle:
        description:
            - VxRail Composite Bundle image.
        type: str
        required: true
    pscroot:
        description:
            - root account for the platform services controller VM
        type: str
        default: root
        required: true
    pscpasswd:
        description:
            - Password for the PSC root user account
        type: str
        required: true
    vcroot:
        description:
            - The root user account for the VCSA.
        type: str
        default: root
        required: true
    vcrootpasswd:
        description:
            - Password for the VCSA root account
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
  - name: collect cluster network address usage
    vx_lcm:
      vcadmin: "{{ vcadmin }}"
      vcpasswd: "{{ vcpasswd}}"
      pscroot: root
      pscpasswd: "{{pscpasswd}}"
      vcroot: root
      vcpasswd: "{{vcrootpasswd}}"
      ip: "{{ vxm_ip }}"
      host: "{{ host }}"
    register: output

  - debug:
      msg: "{{ output }}"
"""

RETURN = """
"""

import time
import datetime
import json
import logging
import requests
import chardet
import urllib3
from requests.exceptions import HTTPError
from ansible.module_utils.basic import AnsibleModule
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CustomLogFormatter(logging.Formatter):
    ''' Docstring '''
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
    ''' Docstring '''
    return json.loads(body.decode(chardet.detect(body)["encoding"]))

# Configurations
LOG_FILE_NAME = datetime.datetime.now().strftime('/tmp/vx-lcm-%Y%m%d.log')
LOG_FORMAT = CustomLogFormatter()

# Disable package info
logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.DEBUG)

# console ouput
CONSOLE_HANDLER = logging.StreamHandler()
CONSOLE_HANDLER.setLevel(logging.INFO)
CONSOLE_HANDLER.setFormatter(LOG_FORMAT)

# file output
FILE_HANDLER = logging.FileHandler(LOG_FILE_NAME)
FILE_HANDLER.setLevel(logging.DEBUG)
FILE_HANDLER.setFormatter(LOG_FORMAT)
LOGGER.addHandler(FILE_HANDLER)

class ExpansionUrls():
    ''' docstring '''
    request_url_tpl = 'https://{}/rest/vxm/v1/requests/{}'
    url_get_system_tpl = 'https://{}/rest/vxm/v1/system'
    v1_lcm_url_tpl = 'https://{}/rest/vxm/v1/lcm/upgrade'
    v2_lcm_url_tpl = 'https://{}/rest/vxm/v2/lcm/upgrade'

    def __init__(self, vxm_ip):
        self.vxm_ip = vxm_ip

    def get_system(self):
        ''' docstring '''
        return ExpansionUrls.url_get_system_tpl.format(self.vxm_ip)

    def post_v1_url_lcm(self):
        ''' docstring '''
        return ExpansionUrls.v1_lcm_url_tpl.format(self.vxm_ip)

    def post_v2_url_lcm(self):
        ''' docstring '''
        return ExpansionUrls.v2_lcm_url_tpl.format(self.vxm_ip)

    def upgrade_progress(self, job_id):
        ''' docstring '''
        return ExpansionUrls.request_url_tpl.format(self.vxm_ip, job_id)

class VxRail():
    ''' docstring '''
    def __init__(self):
        self.vxm_ip = module.params.get('ip')
        self.bundle = module.params.get('bundle')
        self.timeout = module.params.get('timeout')

        self.psc_host = module.params.get('psc_host')
        self.vcsa_psc_host = module.params.get('vcsa_psc_host')
        self.vcsa_tgt_host = module.params.get('vcsa_tgt_psc')

        self.pscroot = module.params.get('pscroot')
        self.vcadmin = module.params.get('vcadmin')
        self.vcroot = module.params.get('vcroot')

        self.pscpasswd = module.params.get('pscpasswd')
        self.vcpasswd = module.params.get('vcpasswd')
        self.vcrootpasswd = module.params.get('vcrootpasswd')
        self.auth = (self.vcadmin, self.vcpasswd)

        self.expansion_urls = ExpansionUrls(self.vxm_ip)

    def extvc_json(self):
        ''' doctstring '''
        lcm_json = {}
        lcm_json['bundle_file_locator'] = self.bundle
        lcm_json['drs_preference'] = {"suggestionAccepted": 'true'}
        vcenter_dict = {}
        vcenter_dict['psc_root_user'] = {'username' : self.pscroot, 'password' : self.pscpasswd}
        vcenter_dict['vc_admin_user'] = {'username' : self.vcadmin, 'password' : self.vcpasswd}
        vcenter_dict['vcsa_root_user'] = {'username' : self.vcroot, 'password' : self.vcrootpasswd}
        lcm_json['vcenter'] = vcenter_dict
        vxrail_dict = {}
        vxrail_dict['vxm_root_user'] = {'username' : 'root', 'password' : self.vcpasswd}
        lcm_json['vxrail'] = vxrail_dict
        witness_dict = {}
        witness_dict['auto_witness_upgrade'] = 'true'
        witness_dict['witness_user'] = {'username' : self.pscroot, 'password' : self.pscpasswd}
        lcm_json['witness'] = witness_dict
        LOGGER.info(lcm_json)
        return lcm_json

    def intvc_json(self):
        ''' Method to construct the JSON payload for the upgrade task  with embedded vCenter'''
        lcm_json = {}
        lcm_json['bundle_file_locator'] = self.bundle
        lcm_json['drs_preference'] = {"suggestionAccepted": 'true'}
        vcenter_dict = {}
        vcenter_dict['psc_root_user'] = {'username' : self.pscroot, 'password' : self.pscpasswd}
        vcenter_dict['vc_admin_user'] = {'username' : self.vcadmin, 'password' : self.vcpasswd}
        vcenter_dict['vcsa_root_user'] = {'username' : self.vcroot, 'password' : self.vcrootpasswd}
        lcm_json['vcenter'] = vcenter_dict
        vxrail_dict = {}
        vxrail_dict['vxm_root_user'] = {'username' : 'root', 'password' : self.vcpasswd}
        lcm_json['vxrail'] = vxrail_dict
        witness_dict = {}
        witness_dict['auto_witness_upgrade'] = 'true'
        witness_dict['witness_user'] = {'username' : self.pscroot, 'password' : self.pscpasswd}
        lcm_json['witness'] = witness_dict
        LOGGER.info(lcm_json)
        return lcm_json



    def v1_upgrade(self, lcm_json):
        ''' Version 1 API branch for VxRail prior to 7.x '''
        response = ''
        try:
            response = requests.post(url=self.expansion_urls.post_v1_url_lcm(),
                                     verify=False,
                                     auth=self.auth,
                                     headers={'Content-type': 'application/json'},
                                     data=json.dumps(lcm_json)
                                     )
            response.raise_for_status()
        except HTTPError as http_err:
            LOGGER.error(response.content)
            LOGGER.error('HTTP error %s request to VxRail Manager %s', http_err, self.vxm_ip)
            return 'error'
        except Exception as err:
            LOGGER.error('%s cannot connect to VxRail Manager %s', err, self.vxm_ip)
            return 'error'

        LOGGER.info(response)
        LOGGER.info('HTTP Response ID: %s', response.status_code)
        if response.status_code == 202:
            response_json = byte_to_json(response.content)
        if 'request_id' not in response_json.keys():
            raise Exception(response_json)
        
        task_id = response_json['request_id']
        LOGGER.info('Pre-validation task started with request id: %s', task_id)
        return task_id

    def v2_upgrade(self, lcm_json):
        ''' Version 2 API branch for VxRail 7 and later '''
        response = ''
        try:
            response = requests.post(url=self.expansion_urls.post_v2_url_lcm(),
                                     verify=False,
                                     auth=self.auth,
                                     headers={'Content-type': 'application/json'},
                                     data=json.dumps(lcm_json)
                                     )
            response.raise_for_status()
        except HTTPError as http_err:
            LOGGER.error(response.content)
            LOGGER.error('HTTP error %s request to VxRail Manager %s', http_err, self.vxm_ip)
            return 'error'
        except Exception as err:
            LOGGER.error('%s cannot connect to VxRail Manager %s', err, self.vxm_ip)
            return 'error'

        LOGGER.info(response)
        LOGGER.info('HTTP Response ID: %s', response.status_code)
        if response.status_code == 202:
            response_json = byte_to_json(response.content)
        if 'request_id' not in response_json.keys():
            raise Exception(response_json)
        task_id = response_json['request_id']
        LOGGER.info('Pre-validation task started with request id: %s', task_id)
        return task_id


    def track_upgrade_progress(self, job_id):
        ''' get task progress '''
        upgrade_progress = ''
        response_json = []
        session = requests.Session()
        try:
            response = session.get(url=self.expansion_urls.upgrade_progress(job_id),
                                   verify=False,
                                   auth=self.auth
                                   )
        except Exception as http_err:
            LOGGER.error(http_err)
            LOGGER.error('Cannot connect to VxRail Manager %s.', self.vxm_ip)
            return 'error'

        if response:
            response_json = byte_to_json(response.content)
        if response_json:
            upgrade_progess = response_json.get('state')
            upgrade_task = response_json.get('detail')
            progress = response_json.get('progress')
            LOGGER.info('Current Status: %s', upgrade_progress)
            LOGGER.info('Progress: %s', progress)
            LOGGER.info('Current Task: %s', upgrade_task)
            if upgrade_progess == 'COMPLETED':
                LOGGER.info("VxRail task has completed")
            elif upgrade_progess == 'FAILED':
                errors = response_json['extension']['errors'][0]
                LOGGER.error(errors['action'])
                LOGGER.error(errors['message'])
            else:
                time.sleep(60)
        return upgrade_progess

    def cluster_version(self):
        ''' query for cluster version '''
        vxm = {}
        response = requests

        try:
            response = requests.get(url=self.expansion_urls.get_system(),
                                    verify=False,
                                    auth=self.auth
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
            LOGGER.info(data)
            vxm['version'] = data['version'][0:3]
            vxm['ext_vc'] = data['is_external_vc']
            vxm['Host Count'] = data['number_of_host']
            vxm['state'] = data['health']
        return vxm

def main():
    ''' Program execution start point '''
    global module
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(required=False),
            bundle=dict(required=True),
            pscroot=dict(required=True),
            pscpasswd=dict(required=True, no_log=True),
            vcadmin=dict(required=True),
            vcpasswd=dict(required=True, no_log=True),
            vcroot=dict(required=True),
            vcrootpasswd=dict(required=True, no_log=True),
            ip=dict(required=True),
            timeout=dict(type='int', default=10),
            ),
        supports_check_mode=True,
    )

    upgrade_status = ''
    LOGGER.info(module.params)
    bundle = (module.params.get('bundle'))
    LOGGER.info(bundle)
    version = VxRail().cluster_version()
    if version.get('ext_vc') == 'true':
        lcm_json = VxRail().extvc_json()
    else:
        lcm_json = VxRail().intvc_json()
    LOGGER.info(lcm_json)
    if version.get('version') in ("4.5", "4.7"):
        taskid = VxRail().v1_upgrade(lcm_json)
    else:
        taskid = VxRail().v2_upgrade(lcm_json)
    if taskid == 'error':
        module.fail_json(msg="VxRail LCM has failed. See /tmp/vx-lcm.log for details")

    LOGGER.info('vxrail_lcm: vxrail task_ID: %s.', taskid)
    while upgrade_status not in ('COMPLETED', 'FAILED'):
        LOGGER.info("vxrail_lcm: sleeping 60 seconds...")
        time.sleep(60)
        upgrade_status = VxRail().track_upgrade_progress(taskid)
        LOGGER.info('vxrail_lcm: track_upgrade_status: %s', upgrade_status)
    if upgrade_status == "FAILED":
        module.fail_json(msg="VxRail Cluster Upgrade Failed. Please see error log for details")
    else:
        vx_facts = {'jobid' : upgrade_status}
        LOGGER.info(upgrade_status)
        vx_facts_result = dict(changed=False, ansible_facts=vx_facts)
        module.exit_json(**vx_facts_result)

if __name__ == '__main__':
    main()
