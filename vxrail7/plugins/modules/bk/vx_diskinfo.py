#!/usr/bin/python3
# Copyright: (c) 2018, Jeff Purcell <jeff.purcell@dell.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
author: Dell EMC Ansible Team (@jpurcell3) <jeff.purcell@dell.com>
module: vx-diskinfo
short_description: VxRail Disk Report
description: Collect VxRail Node disk details at cluster and/or host level

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
      - Optional value to filter and return results for a single node in the cluster
   type: str
   required: false

  failed:
   description:
      - Optional value to filter failed disks
   type: str
   required: false

  Timeout:
    description:
      Time out value for the HTTP session to connect to the REST API
    required: false

version_added: "2.9"

'''

EXAMPLES = """
  - name: Collect Disk Info from VxRail Cluster
    vx-diskinfo:
      ip: " {{vxrail_hosts }}"
      vcadmin: "{{ vcadmin }}"
      vcpasswd: "{{ vcpasswd }}"
  
  - name: Collect Disk Info from VxRail Cluster
    vx-diskinfo:
      ip: " {{vxrail_hosts }}"
      vcadmin: "{{ vcadmin }}"
      vcpasswd: "{{ vcpasswd }}"
      failed: 'yes'

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
LOG_FILE_NAME = "/tmp/vx-disk.log"
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
    system_url_tpl = 'https://{}/rest/vxm/v1/system'
    disks_url_tpl = 'https://{}/rest/vxm/v1/disks'

    def __init__(self, vxm_ip):
        self.vxm_ip = vxm_ip

    def get_disks(self):
        return ExpansionUrls.disks_url_tpl.format(self.vxm_ip)

    def check_system(self):
        return ExpansionUrls.system_url_tpl.format(self.vxm_ip)

class VxRail():
    def __init__(self):
        self.vxm_ip = module.params.get('ip')
        self.timeout = module.params.get('timeout')
        self.admin = module.params.get('vcadmin')
        self.password = module.params.get('vcpasswd')
        self.failed = module.params.get('failed')
        self.expansion_urls = ExpansionUrls(self.vxm_ip)
        response = ''

    def get_disks(self):
        disks = {}
        disklist = []
        try:
            response = requests.get(url=self.expansion_urls.get_disks(),
                                    verify=False,
                                    auth=(self.admin, self.password),
                                    )
            response.raise_for_status()
        except HTTPError as http_err:
            LOGGER.error("HTTP error %s request to VxRail Manager %s", http_err, self.vxm_ip)
            return 'error'
        except Exception as ERR:
            LOGGER.error(' %s Cannot connect to VxRail Manager %s', ERR, self.vxm_ip)
            return 'error'

        if response.status_code == 200:
            data = byte_to_json(response.content)
            if not data:
                return "No available hosts"
            for i in range(len(data)):
                disks['sn'] = data[i].get('sn')
                disks['model'] = data[i].get('model')
                disks['state'] = data[i].get('disk_state')
                disks['capacity'] = data[i].get('capacity')
                disks['enclosure'] = data[i].get('enclosure')
                disks['slot'] = data[i].get('slot')
                disklist.append(dict(disks.items()))
            return disklist

    def get_failed_disks(self):
        disks = {}
        disklist = []
        try:
            response = requests.get(url=self.expansion_urls.get_disks(),
                                    verify=False,
                                    auth=(self.admin, self.password),
                                    )
            response.raise_for_status()
        except HTTPError as http_err:
            LOGGER.error("HTTP error %s request to VxRail Manager %s", http_err, self.vxm_ip)
            return 'error'
        except Exception as ERR:
            LOGGER.error(' %s Cannot connect to VxRail Manager %s', ERR, self.vxm_ip)
            return 'error'

        if response.status_code == 200:
            data = byte_to_json(response.content)
            if not data:
                return "No available hosts"
            for i, t in enumerate(data):
                if not t['disk_state'] == 'OK':
                    disks['sn'] = data[i].get('sn')
                    disks['state'] = data[i].get('disk_state')
                    disks['enclosure'] = data[i].get('enclosure')
                    disks['slot'] = data[i].get('slot')
                    disklist.append(dict(disks.items()))
                return disklist or "No faulty disks"
            return disklist

def main():

    arguments = dict(
        name=dict(required=False),
        vcadmin=dict(required=True),
        vcpasswd=dict(required=True, no_log=True),
        ip=dict(required=True),
        timeout=dict(type='int', default=10),
        failed=dict(required=False),
        )

    required_together = []
    global module
    module = AnsibleModule(
        argument_spec=arguments,
        supports_check_mode=True,
        required_together=required_together
        )

    if (module.params.get('failed') not in ['y', 'yes', 'Yes']):
        result = VxRail().get_disks()
    else:
        result = VxRail().get_failed_disks()
    if result == 'error':
        module.fail_json(msg="VxRail Manager is unreachable")

    vx_facts = {'disks' : result}
    vx_facts_result = dict(changed=False, instance=vx_facts)
    module.exit_json(**vx_facts_result)

if __name__ == '__main__':
    main()
