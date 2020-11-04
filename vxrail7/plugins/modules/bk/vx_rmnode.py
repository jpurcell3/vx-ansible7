#!/usr/bin/python3
''' VxRail Remove Node Module '''
# Copyright: (c) 2020, Jeff Purcell Jones <jeff.purcell@dell.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = '''
author: Dell EMC Ansible Team (@jpurcell3) <jeff.purcell@dell.com>
description:
  - "Remove an existing node from a VxRAil Cluster"

module: vx_rmnode

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

  esxhost:
    description:
      The ESXi Hostname of the host you wish to remove from the cluster
    required: true

  vcsa_user:
    description:
      The vCenter Appliance (port 5480) administrative account (i.e. root).
    required: true

  vcsa_passwd:
    description:
      The vCenter Appliance (port 5480) administrative passwd.
    required: true

  Timeout:
    description:
      Time out value for the HTTP session to connect to the REST API
    required: false

short_description: VxRail Node Removal
version_added: "2.9"

'''

EXAMPLES = """
 -  name: "Remove VxRail Node"
    vx_rmnode:
      ip: "{{ vxm }}"
      vcadmin: "{{ vcadmin }}"
      vcpasswd: "{{ vcpasswd }}"
      esxhost: "{{ esxhost }}"
      vcroot: "{{ vcroot }}"
      vcrootpasswd: "{{ vcrootpasswd }}"
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
from ansible.module_utils.basic import AnsibleModule
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CustomLogFormatter(logging.Formatter):
    ''' Logging method for capturing module output '''
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
    ''' Method to convert http body to json '''
    return json.loads(body.decode(chardet.detect(body)["encoding"]))


# Configurations
LOG_FILE_NAME = "/tmp/rmnode.log"
LOG_FORMAT = CustomLogFormatter()

# Disable package info
logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.DEBUG)

# console ouput
CONSOLE = logging.StreamHandler()
CONSOLE.setLevel(logging.INFO)
CONSOLE.setFormatter(LOG_FORMAT)
LOGGER.addHandler(CONSOLE)

# file output
FILEHANDLER = logging.FileHandler(LOG_FILE_NAME)
FILEHANDLER.setLevel(logging.DEBUG)
FILEHANDLER.setFormatter(LOG_FORMAT)
LOGGER.addHandler(FILEHANDLER)


class ExpansionUrls():
    ''' URL class to expose VxRail APIs as class methods '''
    cluster_hosts_url_tpl = 'https://{}/rest/vxm/v1/system/cluster-hosts'
    shutdown_host_url_tpl = 'https://{}/rest/vxm/v1/hosts/{}/shutdown'
    remove_host_url_tpl = 'https://{}/rest/vxm/v1/cluster/remove-host'
    job_progress_url_tpl = 'https://{}/rest/vxm/v1/requests/{}'

    def __init__(self, vxm_ip):
        self.vxm_ip = vxm_ip

    def get_url_cluster_hosts(self):
        ''' list hosts api '''
        return ExpansionUrls.cluster_hosts_url_tpl.format(self.vxm_ip)

    def get_url_shutdown_host(self, host_sn):
        ''' shutdown api '''
        return ExpansionUrls.shutdown_host_url_tpl.format(self.vxm_ip, host_sn)

    def get_url_remove_host(self, host_sn):
        ''' removal api '''
        return ExpansionUrls.remove_host_url_tpl.format(self.vxm_ip, host_sn)

    def get_url_job_progress(self, job_id):
        ''' VxRail API to tarck job status '''
        return ExpansionUrls.job_progress_url_tpl.format(self.vxm_ip, job_id)

class VxRail():
    ''' main functional class for this module '''
    def __init__(self):
        self.vxm_ip = module.params.get('ip')
        self.hostname = module.params.get('esxhost')
        self.timeout = module.params.get('timeout')
        self.user = module.params.get('vcadmin')
        self.password = module.params.get('vcpasswd')
        self.auth = (self.user, self.password)
        self.vcsa_user = module.params.get('vcroot')
        self.vcsa_passwd = module.params.get('vcrootpasswd')
        self.expansion_urls = ExpansionUrls(self.vxm_ip)

    def get_host_info(self):
        ''' get host list '''
        host_data = []
        api_url = self.expansion_urls.get_url_cluster_hosts()
        response = requests.get(url=api_url,
                                verify=False,
                                auth=self.auth,
                                timeout=self.timeout)
        if not response:
            module.fail_json(msg="No valid or no response from url %s within %s \
                             seconds (timeout)" % (api_url, self.timeout))
        data = byte_to_json(response.content)
        LOGGER.info(data)
        LOGGER.info('Host info length is %d', len(data))
        
        if len(data) == 0:
            return []
        if len(data) in range(1,4):
            return "The cluster is at the minumum node count. Node cannot be removed!"
        for item in data:
            if (item.get('host_name')) == self.hostname:
                host_sn = item.get('serial_number')
                op_status = item.get('operational_status')
                power = item.get('power_status')
                host_data = [host_sn, op_status, power]
        return host_data


    def create_node_json(self, host_sn):
        ''' create node removal payload '''
        node_json = {}
        node_json = {}
        node_json['serial_number'] = host_sn
        vc_admin_dict = {}
        vc_admin_dict['username'] = self.user
        vc_admin_dict['password'] = self.password
        vcsa_root_dict = {}
        vcsa_root_dict['username'] = self.vcsa_user
        vcsa_root_dict['password'] = self.vcsa_passwd
        node_json['vc_admin_user'] = vc_admin_dict
        node_json['vcsa_root_user'] = vcsa_root_dict
        return node_json

    def shutdown_esx_host(self, host_sn, node_json):
        ''' shutdown node '''
        data = json.dumps(node_json)
        shutdown_url = self.expansion_urls.get_url_shutdown_host(host_sn)
        response_body = requests.post(
                        url=shutdown_url,
                        verify=False,
                        auth=self.auth,
                        data=data)
        response_json = byte_to_json(response_body.content)
        return response_json

    def remove_vxhost(self, host_sn, node_json):
        ''' remove node '''
        json_data = json.dumps(node_json)
        remove_url = self.expansion_urls.get_url_remove_host(host_sn)
        response_body = requests.post(
                        url=remove_url,
                        verify=False,
                        auth=self.auth,
                        data=json_data)
        response_json = byte_to_json(response_body.content)
        request_id = response_json['request_id']
        return request_id

    def track_shutdown_progress(self, job_id):
        ''' track progress of node shutdown '''
        sleep_time = 5
        progress_url = self.expansion_urls.get_url_job_progress(job_id)
        while 1:
            time.sleep(sleep_time)
            response = requests.get(
                url=progress_url,
                verify=False,
                auth=self.auth
                )
            if response:
                response_json = byte_to_json(response.content)
                shutdown_status = response_json["state"]
            if shutdown_status == 'COMPLETED':
                LOGGER.info("Node validation has completed")
            elif shutdown_status == 'FAILED':
                LOGGER.info('Node Shutdown Task %s has failed.', job_id)
                LOGGER.info(response_json['extension']['normalValidationFieldErrors'])
            else:
                LOGGER.info('Shutdown Task is running...')
                LOGGER.info("Sleeping 5 seconds...")
                time.sleep(5)
            return shutdown_status

    def track_remove_progress(self, job_id):
        ''' track vxrail removal task '''
        progress_url = self.expansion_urls.get_url_job_progress(job_id)
        session = requests.Session()
        response = session.get(
            url=progress_url,
            verify=False,
            auth=self.auth
                )
        if response:
            response_json = byte_to_json(response.content)
            removal_status = response_json["state"]
            LOGGER.info('Removal status: %s', removal_status)
            if removal_status == 'COMPLETED':
                LOGGER.info("Node has been succesully removed")
            elif removal_status == 'FAILED':
                LOGGER.info('Node removal task %s has failed.', job_id)
                error = response_json['extension'][-1]
                LOGGER.info(error['name'])
                LOGGER.info(error['message'])
            else:
                LOGGER.info(removal_status)
                LOGGER.info('Node Removal in progress: Sleeping 5 seconds...')
                time.sleep(5)
        return removal_status

def main():
    ''' start here '''
    global module
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(required=False),
            vcadmin=dict(required=True),
            vcpasswd=dict(required=True, no_log=True),
            ip=dict(required=True),
            esxhost=dict(required=True),
            vcroot=dict(required=True),
            vcrootpasswd=dict(required=True, no_log=True),
            timeout=dict(type='int', default=10),
            ),
        supports_check_mode=True,
    )

    status = 'Node Not Removed'
    host_info = VxRail().get_host_info()
    LOGGER.info('Host info details: %s.', host_info)
    if len(host_info) == 0:
        module.fail_json(msg="VxRail Host not Found!")
    if isinstance(host_info, str):
        status = host_info
    else:
        node_json = VxRail().create_node_json(host_info[0])
        LOGGER.info(host_info[2])
        if host_info[2] == 'on' or host_info[2] == 'maintenance':
            shutdown_dict = VxRail().shutdown_esx_host(host_info[0], node_json)
            shutdown_id = shutdown_dict.get('request_id')
            status = VxRail().track_shutdown_progress(shutdown_id)
        while (host_info[2]) == 'on':
            host_info = VxRail().get_host_info()
            time.sleep(5)
    if host_info[2] == 'off':
        remove_id = VxRail().remove_vxhost(host_info[0], node_json)
        while status not in ('COMPLETED' or 'FAILED'):
            LOGGER.info('remove_node: %s', remove_id)
            status = VxRail().track_remove_progress(remove_id)
            LOGGER.info(status)
            time.sleep(30)

    vx_facts = {'task_status' : status}
    vx_facts_result = dict(changed=True, ansible_facts=vx_facts)
    module.exit_json(**vx_facts_result)

if __name__ == '__main__':
    main()
