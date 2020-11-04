#!/usr/bin/python3

'''
# Copyright: (c) 2018, Jeff Purcell <jeff.purcell@dell.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
'''


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
author:  Dell EMC VxRail Ansible Team (@jpurcell3) <jeff.purcell@dell.com>
module: vx_nodes
short_description: This module is used a simple tool to return the inventory of confirued nodes.

description: Module returns the VxRali Log Bundle for the cluster
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
    host:
        description:
            - Optional value to filter and return results for a single node in the cluster
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
   vx_nodes:
     vcadmin: "{{ vcadmin }}"
     vcpasswd: "{{ vcpasswd}}"
     vxm: "{{ vxm }}"
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
import urllib3
from requests.exceptions import HTTPError
from ansible.module_utils.basic import AnsibleModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CustomLogFormatter(logging.Formatter):
    ''' Logging Class for Module '''
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
    ''' Method for converting http content to json format'''
    return json.loads(body.decode(chardet.detect(body)["encoding"]))

# Configurations
LOG_FILE_NAME = "/tmp/vx-log.log"
LOG_FORMAT = CustomLogFormatter()

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.DEBUG)

# file output
FILE_HANDLER = logging.FileHandler(LOG_FILE_NAME)
FILE_HANDLER.setLevel(logging.DEBUG)
FILE_HANDLER.setFormatter(LOG_FORMAT)
LOGGER.addHandler(FILE_HANDLER)

class ExpansionUrls():
    ''' Mapping class for VxRail APIs '''
    vxlog_url_tpl = 'https://{}/rest/vxm/v1/support/logs'
    vxtask_tpl = 'https://{}/rest/vxm/v1/requests/{}'

    def __init__(self, vxm_ip):
        self.vxm_ip = vxm_ip

    def request_logs(self):
        ''' VxRail get node list api '''
        return ExpansionUrls.vxlog_url_tpl.format(self.vxm_ip)

    def get_task(self, task_id):
        ''' VxRail get node details api '''
        return ExpansionUrls.vxtask_tpl.format(self.vxm_ip, task_id)


class VxRail():
    ''' main module class for all methods '''
    def __init__(self):
        self.vxm_ip = module.params.get('ip')
        self.vcadmin = module.params.get('vcadmin')
        self.vcpasswd = module.params.get('vcpasswd')
        self.auth = (self.vcadmin, self.vcpasswd)
        self.expansion_urls = ExpansionUrls(self.vxm_ip)

    def get_logs(self):
        ''' doc '''
        task_id = ''
        payload = VxRail().get_json()
        headers = {'Content-type': 'application/json'}
        LOGGER.info(payload)

        try:
            response = requests.post(url=self.expansion_urls.request_logs(),
                                     verify=False,
                                     auth=(self.vcadmin, self.vcpasswd),
                                     headers=headers,
                                     data=json.dumps(payload))
            response.raise_for_status()
        except HTTPError as http_err:
            LOGGER.error("HTTP error %s request to VxRail Manager %s", http_err, self.vxm_ip)
            return 'error'
        except Exception as api_exception:
            LOGGER.error(' %s Cannot connect to VxRail Manager %s', api_exception, self.vxm_ip)
            return 'error'

        if response.status_code == 202:
            task_id = byte_to_json(response.content)
            if not task_id:
                return "Log generation request failed"
        return task_id['request_id']


    def get_json(self):
        ''' Static json file '''
        log_json = {}
        log_json['autoclean'] = 'true'
        log_json['types'] = ["vxm"]
        return log_json

    def track_status(self, tid):
        ''' track the job status '''
        task_status = ''
        log_path = ''
        session = requests.Session()
        while task_status not in ('COMPLETED', 'FAILED'):
            try:
                response = session.get(url=self.expansion_urls.get_task(tid),
                                       verify=False,
                                       auth=self.auth,
                                       )
            except Exception as http_err:
                LOGGER.error(http_err)
                LOGGER.error('Cannot connect to VxRail Manager %s.', self.vxm_ip)

            LOGGER.info(response.status_code)
            response_json = byte_to_json(response.content)
            percent = response_json.get('progress')
            LOGGER.info('Percent completed: %d', percent)
            task_status = response_json.get('state')
            LOGGER.info('Status: %s', task_status)
            if task_status == 'COMPLETED':
                LOGGER.info("The log bundle creation has completed")
                log_path = response_json['extension'].get('path')
                LOGGER.info("The log bundle creation has completed")
                LOGGER.info('The log location is %s', log_path)
            elif task_status == 'FAILED':
                LOGGER.info('Log Creation Task %s has failed.', tid)
                exit
            else:
                LOGGER.info('Inner track_log_creation method: %s', task_status)
                time.sleep(60)

        return log_path

def main():
    ''' doc '''
    result = ''
    global module
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(required=False),
            vcadmin=dict(default='administrator@vsphere.local'),
            vcpasswd=dict(required=True, no_log=True),
            ip=dict(required=True),
            ),
        supports_check_mode=True,
    )

    task_id = VxRail().get_logs()
    if task_id:
        LOGGER.info('Task id is %s', task_id)
    if task_id == 'error':
        module.fail_json(msg="VxRail Manager is unreachable")

    if (len(task_id)) == 0:
        module.fail_json(msg="Log creation task failedLog. Check /tmp/vx-logs.log for details")
    log_path = VxRail().track_status(task_id)
    LOGGER.info(log_path)
    if log_path:
        vx_facts = {'file_path' : log_path}
        vx_facts_result = dict(changed=False, ansible_facts=vx_facts)
        module.exit_json(**vx_facts_result)

    vx_facts_result = dict(changed=False, ansible_facts=result)
    module.exit_json(**vx_facts_result)

if __name__ == '__main__':
    main()
