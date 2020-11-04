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
import json
import logging
import requests
import chardet
from requests.exceptions import HTTPError
from ansible.module_utils.basic import AnsibleModule
requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)

class CustomLogFormatter(logging.Formatter):
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
    return json.loads(body.decode(chardet.detect(body)["encoding"]))

# Configurations
LOG_FILE_NAME = "/tmp/vx-lcm.log"
LOG_FORMAT = CustomLogFormatter()

# Disable package info
logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger('requests.urllib3').setLevel(logging.WARNING)

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
    request_url_tpl = 'https://{}/rest/vxm/v1/requests/{}'
#    lcm_url_tpl = 'https://{}/rest/vxm/v1/lcm/upgrade'
    lcm_url_tpl = 'https://{}/rest/vxm/v1/lcm/upgrade'
    vc_mode_tpl = 'https://{}/rest/vxm/v1/vc/mode'


    def __init__(self, vxm_ip):
        self.vxm_ip = vxm_ip

    def post_url_lcm(self):
        return ExpansionUrls.lcm_url_tpl.format(self.vxm_ip)

    def upgrade_progress(self, job_id):
        return ExpansionUrls.request_url_tpl.format(self.vxm_ip, job_id)

    def getvc_mode(self):
        '''return the current vcenter configuration settings'''
        return ExpansionUrls.vc_mode_tpl.format(self.vxm_ip)


class VxRail():
    def __init__(self):
        self.vxm_ip = module.params.get('ip')
        self.bundle = module.params.get('bundle')
        self.timeout = module.params.get('timeout')

        self.pschost = module.params.get('psc_host')
        self.vcsa_host = module.params.get('vcsa_host')
        self.tmpvcsa = module.params.get('tmpvcsa')

        self.pscroot = module.params.get('pscroot')
        self.vcadmin = module.params.get('vcadmin')
        self.vcroot = module.params.get('vcroot')

        self.pscpasswd = module.params.get('pscpasswd')
        self.vcpasswd = module.params.get('vcpasswd')
        self.vcrootpasswd = module.params.get('vcrootpasswd')
        self.auth = (self.vcadmin, self.vcpasswd)

        self.expansion_urls = ExpansionUrls(self.vxm_ip)
        self.tmpip = module.params.get('tmpip')
        self.mask = module.params.get('mask')
        self.gw = module.params.get('gw')


    def extvc_json(self):
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
#        LOGGER.info(lcm_json)
        return lcm_json


    def intvc_json(self):
        lcm_json = {}
        lcm_json['bundle_file_locator'] = self.bundle
        lcm_json['drs_preference'] = {'suggestionAccepted': 'true'}
#        lcm_json['upgrade_sequence'] = {'preferred_fault_domain_first': 'true'}
        migration = {}
        migration['source_psc_host'] = {'name': self.pschost, 'user' : {'username' : self.pscroot, 'password' : self.pscpasswd}}
        migration['source_vcsa_host'] = {'name': self.vcsa_host, 'user' : {'username' : self.vcroot, 'password' : self.vcrootpasswd}}
        migration['target_vcsa_host'] = {'name': self.tmpvcsa, 'user' : {'username' : self.vcroot, 'password' : self.vcrootpasswd}}
        migration['temporary_ip_setting'] = {"gateway": self.gw, "netmask": self.mask, "tempIpVerified": 'true', "temporaryIp": self.tmpip, "temporary_ip": self.tmpip}
        vcenter_dict = {}
        vcenter_dict['migration_spec'] = migration
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
#        LOGGER.info(lcm_json)
        return lcm_json



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


    def upgrade_cluster(self, lcm_json):
        self.headers = {'Content-type': 'application/json'}
        response = ''
        try:
            response = requests.post(url=self.expansion_urls.post_url_lcm(),
                                     verify=False,
                                     auth=self.auth,
                                     headers=self.headers,
                                     data=json.dumps(lcm_json)
                                     )
            response.raise_for_status()
        except HTTPError as http_err:
            LOGGER.info('HTTP Response ID: %d', response.status_code)
            LOGGER.error('HTTP error %s request to VxRail Manager %s', http_err, self.vxm_ip)
            response_json = byte_to_json(response.content) 
            if response_json['error']:
                vx_err = response_json['error']
                LOGGER.error('Request failed with error %s ', vx_err)
            else:
                vx_err = 'error'
            return vx_err
        except Exception as err:
            LOGGER.info('HTTP Response ID: %d', response.status_code)
            LOGGER.error('%s request resulted in an exception %s', err, self.vxm_ip)
            response_json = byte_to_json(response.content)
            if response_json['error']:
                vx_err = response_json['error']
                LOGGER.error('Request failed with error %s ', vx_err)
            else:
                vx_err = 'error'
            return 'vx_err'

        LOGGER.info(response)
        LOGGER.info('HTTP Response ID: %d', response.status_code)
        if response.status_code == 202:
            response_json = byte_to_json(response.content)
        if 'request_id' not in response_json.keys():
            raise Exception(response_json)
        else:
            task_id = response_json['request_id']
            response_json = byte_to_json(response.content)
            LOGGER.info('Pre-validation task started with request id: %s', task_id)
        return task_id


    def track_upgrade_progress(self, job_id):
        ''' get task progress '''
        upgrade_state = ''
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
                upgrade_state = response_json.get('state')
                upgrade_task = response_json.get('detail')
                progress = response_json.get('progress')
                LOGGER.info('Current Status: %s', upgrade_state)
                LOGGER.info('Progress: %s', progress)
                LOGGER.info('Current Task: %s', upgrade_task)
                if upgrade_progess == 'COMPLETED':
                    LOGGER.info("VxRail task has completed")
                elif upgrade_progess == 'FAILED':
                    errors = response_json['extension']['errors'][0]
                    LOGGER.error(errors['action'])
                    LOGGER.error(errors['message'])
        # write module to compare current upgrade task to previous upgrade task. If ==, sleep 
        return upgrade_state


def main():
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
            gw=dict(required=True),
            mask=dict(required=True),
            tmpip=dict(required=True),
            psc_host=dict(required=True),
            vcsa_host=dict(required=True),
            tmpvcsa=dict(required=True),
            timeout=dict(type='int', default=10),
            ),
        supports_check_mode=True,
    )

    upgrade_status = ''
#    LOGGER.info(module.params)
    bundle = (module.params.get('bundle'))
    LOGGER.info(bundle)
    if VxRail().get_vc_mode() == 'EMBEDDED':
        lcm_json = VxRail().intvc_json()
    else:
        lcm_json = VxRail().extvc_json()
    LOGGER.info(lcm_json)
    taskid = VxRail().upgrade_cluster(lcm_json)
    if taskid == 'error':
        
        module.fail_json(msg="VxRail Upgrade has failed to complete")

    LOGGER.info('vxrail_lcm: vxrail task_ID: %s.', taskid)
    while upgrade_status not in ('COMPLETED', 'FAILED'):
        LOGGER.info("vxrail_lcm: sleeping 2 minutes...")
        time.sleep(120)
        upgrade_state = VxRail().track_upgrade_progress(taskid)
        LOGGER.info('vxrail_lcm: track_upgrade_status: %s', upgrade_state)
    if upgrade_status == "FAILED":
        module.fail_json(msg="VxRail Cluster Upgrade Failed. Please see error log for details")
    else:
        vx_facts = {'jobid' : upgrade_status}
        LOGGER.info(upgrade_status)
        vx_facts_result = dict(changed=False, ansible_facts=vx_facts)
        module.exit_json(**vx_facts_result)

if __name__ == '__main__':
    main()
