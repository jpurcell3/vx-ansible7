#!/usr/bin/python3
# Copyright: (c) 2018, Jeff Purcell <jeff.purcell@dell.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
author:  Dell EMC VxRail Ansible Team (@jpurcell3) <jeff.purcell@dell.com>
module: vx_netinfo
short_description: This module is used to collect network configuration details on a VxRail Cluster

description: The module reliease upon the VxRail network API to return details of the ESXi Nodes. The script includes filters to limit the properties returned by the module.
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
   vx_netinfo:
     vcadmin: "{{ vcadmin }}"
     vcpasswd: "{{ vcpasswd}}"
     vxm: "{{ vxm }}"
     host: "{{ host }}"
   register: output

 - debug:
     msg: "{{ output }}"
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
LOG_FILE_NAME = "/tmp/vx-netinfo.log"
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
    hosts_url_tpl = 'https://{}/rest/vxm/v1/hosts'
    node_url_tpl = 'https://{}/rest/vxm/v1/hosts/{}'
    get_url_idrac_tpl = 'https://{}/rest/vxm/v1/hosts/{}/idrac/network'
    get_ip_allocation_tpl = 'https://{}/rest/vxm/private/system/network-info'

    def __init__(self, vxm_ip):
        self.vxm_ip = vxm_ip

    def get_hosts(self):
        ''' VxRail get node list api '''
        return ExpansionUrls.hosts_url_tpl.format(self.vxm_ip)

    def get_node(self, node_sn):
        ''' VxRail get node details api '''
        return ExpansionUrls.node_url_tpl.format(self.vxm_ip, node_sn)

    def get_idrac_ip(self, host_sn):
        ''' idrac api '''
        return ExpansionUrls.get_url_idrac_tpl.format(self.vxm_ip, host_sn)

    def get_ipuse(self):
        ''' netinfo api '''
        return ExpansionUrls.get_ip_allocation_tpl.format(self.vxm_ip)


class VxRail():
    ''' main module class for all methods '''
    def __init__(self):
        self.vxm_ip = module.params.get('ip')
        self.timeout = module.params.get('timeout')
        self.vcadmin = module.params.get('vcadmin')
        self.vcpasswd = module.params.get('vcpasswd')
        self.auth = (self.vcadmin, self.vcpasswd)
        self.esx = module.params.get('host')
        self.timeout = module.params.get('timeout')
        self.expansion_urls = ExpansionUrls(self.vxm_ip)

    def get_host(self):
        ''' doc '''
        rpt = []
        host = {}
        nic_dict = {}
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
        for item in data:
            hostname = item.get('hostname')
            if hostname != self.esx:
                pass
            else:
                nlist = []
                host['Name'] = hostname
                host['Id'] = item.get('id')
                host['idrac_ip'] = self.get_idrac_ip(host['Id'])
                nic_list = (item.get('nics'))
                for n in nic_list:
                    nic_dict['mac'] = n.get('mac')
                    nic_dict['link_status'] = n.get('link_status')
                    nic_dict['link_speed'] = n.get('link_speed')
                    nic_dict['firmware'] = n.get('firmware_family_version')
                    nlist.append(dict(nic_dict))
                host['nics'] = nlist
#                LOGGER.info(host)
                rpt.append(dict(host))
        return rpt


    def get_allhosts(self):
        ''' doc '''
        rpt = []
        host = {}
        nic_dict = {}
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
        for item in data:
            nlist = []
            hostname = item.get('hostname')
            host['Name'] = hostname
            host['Id'] = item.get('id')
            host['Operational_Status'] = item.get('operational_status')
            host['idrac_ip'] = self.get_idrac_ip(host['Id'])
            nic_list = (item.get('nics'))
            for n in nic_list:
                for key, value in n.items():
                    nic_dict['mac'] = n.get('mac')
                    nic_dict['link_status'] = n.get('link_status')
                    nic_dict['link_speed'] = n.get('link_speed')
                    nic_dict['firmware'] = n.get('firmware_family_version')
                nlist.append(dict(nic_dict))
                host['nics'] = nlist
#            LOGGER.info(host)
            rpt.append(dict(host))
        ip_dict = VxRail().get_ipdict()
        LOGGER.info(ip_dict)
        rpt.append(dict(ip_dict))
        return rpt

    def get_ipdict(self):
        ''' doc '''
        nic_data = {}
        try:
            response = requests.get(url=self.expansion_urls.get_ipuse(),
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
            nic_data = byte_to_json(response.content)
            if not nic_data:
                return "Network info is unavailable"
#            LOGGER.info(nic_data)
            return nic_data


    def get_idrac_ip(self, sn):
        ''' get host list '''
        api_url = self.expansion_urls.get_idrac_ip(sn)
        try:
            response = requests.get(url=api_url,
                                    verify=False,
                                    auth=self.auth,
                                    timeout=self.timeout)
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            LOGGER.error('Get Host Method error: %s', err)
            module.fail_json(msg="No valid or no response from url %s within %s \
                             seconds (timeout)" % (api_url, self.timeout))
        data = byte_to_json(response.content)
        idrac_ip = data['ip']['ip_address']
        return idrac_ip


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
            host=dict(required=False),
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
        result = "No hosts found. Confirm hostname and retry"

    vx_facts = {'hosts' : result}
    vx_facts_result = dict(changed=False, ansible_facts=vx_facts)
    module.exit_json(**vx_facts_result)

    vx_facts_result = dict(changed=False, ansible_facts=result)
    module.exit_json(**vx_facts_result)

if __name__ == '__main__':
    main()
