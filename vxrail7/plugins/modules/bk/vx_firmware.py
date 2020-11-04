#!/usr/bin/python3
''' VxRail Firmware Inventory Module '''
# Copyright: (c) 2018, Jeff Purcell <jeff.purcell@dell.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = '''
author: Dell EMC Ansible Team (@jpurcell3) <jeff.purcell@dell.com>
module: vx_firmware
description:
  - "Collect the Firmware Inventory for Single Cluster"

options:

  ip:
    description:
      The IP address of the VxRail Manager System
    required: true

  vcadmin:
    description:
      Administrative account of the vCenter Server the VxRail Manager is registeried to
    required: true

  vcpasswd:
    description:
      The password for the administror account provided in vcadmin
    required: true

  host:
    description:
      Optional vxrail esx hostname to restrict output.
    required: false

  Timeout:
    description:
      Time out value for the HTTP session to connect to the REST API
    required: false

short_description: VxRail Firmware Report
version_added: "2.9"

'''

EXAMPLES = """
    - name: Collect Disk Info from VxRail Cluster
      vx-firmware
        ip: "{{vxm}}"
        vcadmin: "{{vcadmin}}"
        vcpasswd: "{{vcpasswd}}"
        host: "{{host}}"
"""

RETURN = """
"""


import json
import logging
import requests
import chardet
import urllib3
from requests.exceptions import HTTPError
from ansible.module_utils.basic import AnsibleModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CustomLogFormatter(logging.Formatter):
    ''' class to peform logging for module '''
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
    ''' method to convert http body to json '''
    return json.loads(body.decode(chardet.detect(body)["encoding"]))


# Configurations
LOG_FILE_NAME = "/tmp/vx-firmware.log"
LOG_FORMAT = CustomLogFormatter()

# Disable package info
logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.DEBUG)

# file output
FILEHANDLER = logging.FileHandler(LOG_FILE_NAME)
FILEHANDLER.setLevel(logging.DEBUG)
FILEHANDLER.setFormatter(LOG_FORMAT)
LOGGER.addHandler(FILEHANDLER)

class ExpansionUrls():
    ''' class to map vxrail api's to methods '''
    hosts_url_tpl = 'https://{}/rest/vxm/v1/hosts'
    node_url_tpl = 'https://{}/rest/vxm/v1/hosts/{}'

    def __init__(self, vxm_ip):
        self.vxm_ip = vxm_ip

    def get_hosts(self):
        ''' api to get list of hosts '''
        return ExpansionUrls.hosts_url_tpl.format(self.vxm_ip)

    def get_node(self, node_sn):
        ''' api to get specific host '''
        return ExpansionUrls.node_url_tpl.format(self.vxm_ip, node_sn)

class VxRail():
    ''' primary class for module '''
    def __init__(self):
        self.vxm_ip = module.params.get('ip')
        self.timeout = module.params.get('timeout')
        self.vcadmin = module.params.get('vcadmin')
        self.vcpasswd = module.params.get('vcpasswd')
        self.esx = module.params.get('host')
        self.expansion_urls = ExpansionUrls(self.vxm_ip)

    def get_host(self):
        ''' return a list of hosts '''
        rpt = []
        host = {}
        fw_dict = {}
        try:
            response = requests.get(url=self.expansion_urls.get_hosts(),
                                    verify=False,
                                    auth=(self.vcadmin, self.vcpasswd),
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
            if not data:
                return "No available hosts"

        for i, d in enumerate(data):
            hostname = d.get('hostname')
            if hostname != self.esx:
                pass
            else:
                host['Name'] = hostname
                fw_dict = (d.get('firmwareInfo'))
                for key, value in fw_dict.items():
                    fw_dict[key] = value
                host['system-firmware'] = fw_dict
                LOGGER.info(host)
                rpt.append(dict(host))
        return rpt

    def get_allhosts(self):
        ''' return a list of hosts '''
        rpt = []
        host = {}
        fw_dict = {}
        try:
            response = requests.get(url=self.expansion_urls.get_hosts(),
                                    verify=False,
                                    auth=(self.vcadmin, self.vcpasswd),
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
            if not data:
                return "No available hosts"

        for i, d in enumerate(data):
            hostname = d.get('hostname')
            host['name'] = hostname
            fw_dict = (d.get('firmwareInfo'))
            for key, value in fw_dict.items():
                fw_dict[key] = value
            LOGGER.info(host)
            LOGGER.info(fw_dict)
            host['system-firmware'] = fw_dict
            rpt.append(dict(host))
        return rpt


def main():
    ''' main entry point into module '''
    result = ''
    global module
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(required=False),
            vcadmin=dict(type='str', default='administrator@vsphere.local'),
            vcpasswd=dict(required=True, no_log=True),
            ip=dict(required=True),
            host=dict(type='str', required=False),
            timeout=dict(type='int', default=10),
            ),
        supports_check_mode=True,
    )

    if (not(module.params.get('host')) or (module.params.get('host') == 'all')):
        result = VxRail().get_allhosts()
    else:
        result = VxRail().get_host()
    LOGGER.info(result)

    if result == 'error':
        module.fail_json(msg="VxRail Manager is unreachable")
    if len(result) == 0:
        module.fail_json(msg="No hosts found. Confirm hostname and retry")

    vx_facts = {'hosts' : result}
    vx_facts_result = dict(changed=False, ansible_facts=vx_facts)
    module.exit_json(**vx_facts_result)

    vx_facts_result = dict(changed=False, ansible_facts=result)
    module.exit_json(**vx_facts_result)


if __name__ == '__main__':
    main()
